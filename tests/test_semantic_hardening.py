"""Tests for semantic hardening and execution-alignment constraints.

Validates ActionEvent validation, JSON serializability, Capability regex parsing, and isolated ReplayEngine.
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from capfence.core.runtime import ActionEvent, ActionRuntime
from capfence.core.capabilities import Capability, CapabilitySystem
from capfence.core.approvals import ApprovalEngine
from capfence.core.audit import ImmutableAuditTrail
from capfence.core.replay import ReplayEngine


def test_action_event_validations() -> None:
    # 1. Test empty parameters raise ValueErrors
    with pytest.raises(ValueError, match="actor must be a non-empty string"):
        ActionEvent(actor="", action="read", resource="fs", environment="prod", risk="low")

    with pytest.raises(ValueError, match="action must be a non-empty string"):
        ActionEvent(actor="agent", action="", resource="fs", environment="prod", risk="low")

    with pytest.raises(ValueError, match="resource must be a non-empty string"):
        ActionEvent(actor="agent", action="read", resource="", environment="prod", risk="low")

    # 2. Test invalid risk types and scores
    with pytest.raises(ValueError, match="risk string must be one of"):
        ActionEvent(actor="agent", action="read", resource="fs", environment="prod", risk="super-high")

    with pytest.raises(ValueError, match="risk score must be a non-negative float"):
        ActionEvent(actor="agent", action="read", resource="fs", environment="prod", risk=-0.5)

    with pytest.raises(ValueError, match="risk must be a string or a float"):
        ActionEvent(actor="agent", action="read", resource="fs", environment="prod", risk=[])  # type: ignore

    # 3. Test strict JSON-serializability check on metadata to prevent replay instability
    def sample_func():
        pass

    with pytest.raises(ValueError, match="metadata must be completely JSON-serializable"):
        ActionEvent(
            actor="agent",
            action="read",
            resource="fs",
            environment="prod",
            risk="low",
            metadata={"func_ref": sample_func}
        )

    # 4. Test strict whitelisted metadata keys
    with pytest.raises(ValueError, match="Metadata key 'invalid_key_xyz' is invalid"):
        ActionEvent(
            actor="agent",
            action="read",
            resource="fs",
            environment="prod",
            risk="low",
            metadata={"invalid_key_xyz": "some_value"}
        )

    # 5. Test strict type validation on metadata fields
    with pytest.raises(ValueError, match="metadata\\['session_id'\\] must be a string"):
        ActionEvent(
            actor="agent",
            action="read",
            resource="fs",
            environment="prod",
            risk="low",
            metadata={"session_id": 12345}  # Should be string
        )

    with pytest.raises(ValueError, match="metadata\\['require_approval'\\] must be a boolean"):
        ActionEvent(
            actor="agent",
            action="read",
            resource="fs",
            environment="prod",
            risk="low",
            metadata={"require_approval": "yes"}  # Should be boolean
        )


def test_capability_regex_parsing() -> None:
    # 1. Test valid capability characters
    c1 = Capability.parse("aws.ec2-terminate.main_branch")
    assert c1.resource == "aws"
    assert c1.action == "ec2-terminate"
    assert c1.scope == "main_branch"

    # 2. Test invalid space characters
    with pytest.raises(ValueError, match="Capability string contains invalid characters"):
        Capability.parse("aws.ec2 terminate.main")

    # 3. Test empty/null strings
    with pytest.raises(ValueError, match="Capability string must be a non-empty string"):
        Capability.parse("")


def test_replay_engine_absolute_isolation(tmp_path: Path) -> None:
    # Set up a real SQLite database for approvals and audit logs
    real_db_path = tmp_path / "real_approvals.db"
    real_audit_path = tmp_path / "real_audit.db"

    real_approval = ApprovalEngine(db_path=real_db_path)
    real_audit = ImmutableAuditTrail(db_path=real_audit_path)

    # Pre-populate a policy allowing 'fs.read.*'
    caps = CapabilitySystem()
    caps.allowed.append(Capability.parse("fs.read.*"))

    runtime = ActionRuntime(
        capability_system=caps,
        approval_engine=real_approval,
        audit_trail=real_audit,
        mode="enforce"
    )

    # Trace containing 1 event
    trace_data = [
        {"capfence_replay_version": "1.0", "checksum": "ignore"},
        {
            "actor": "agent-1",
            "action": "read",
            "resource": "fs",
            "environment": "production",
            "risk": "low",
            "decision": "pass"
        }
    ]
    trace_file = tmp_path / "test_trace.json"
    with open(trace_file, "w", encoding="utf-8") as f:
        json.dump(trace_data, f)

    engine = ReplayEngine(runtime=runtime)
    summary = engine.replay_incident(trace_file)

    assert summary.total_events == 1
    assert summary.authorized == 1

    # Verify that the live SQLite audit log has ZERO entries, preserving absolute state isolation!
    events = real_audit.get_events()
    assert len(events) == 0


def test_replay_engine_missing_version_header_fails_closed(tmp_path: Path) -> None:
    trace_data = [
        {"actor": "agent-1", "action": "read", "resource": "fs", "environment": "production", "risk": "low"}
    ]
    trace_file = tmp_path / "bad_trace.json"
    with open(trace_file, "w", encoding="utf-8") as f:
        json.dump(trace_data, f)
        
    engine = ReplayEngine()
    with pytest.raises(ValueError, match="Trace is missing the mandatory 'capfence_replay_version'"):
        engine.replay_incident(trace_file)


def test_replay_engine_invalid_version_fails_closed(tmp_path: Path) -> None:
    trace_data = [
        {"capfence_replay_version": "2.0", "checksum": "ignore"},
        {"actor": "agent-1", "action": "read", "resource": "fs", "environment": "production", "risk": "low"}
    ]
    trace_file = tmp_path / "bad_trace.json"
    with open(trace_file, "w", encoding="utf-8") as f:
        json.dump(trace_data, f)
        
    engine = ReplayEngine()
    with pytest.raises(ValueError, match="Unsupported replay trace version: 2.0"):
        engine.replay_incident(trace_file)


def test_replay_engine_checksum_integrity_verification_fails_closed(tmp_path: Path) -> None:
    trace_data = [
        {"capfence_replay_version": "1.0", "checksum": "wrong-checksum-hash"},
        {"actor": "agent-1", "action": "read", "resource": "fs", "environment": "production", "risk": "low"}
    ]
    trace_file = tmp_path / "bad_trace.json"
    with open(trace_file, "w", encoding="utf-8") as f:
        json.dump(trace_data, f)
        
    engine = ReplayEngine()
    with pytest.raises(ValueError, match="Replay integrity verification failed: trace checksum mismatch"):
        engine.replay_incident(trace_file)


def test_cryptographically_signed_grants_fail_closed_on_tampering() -> None:
    approvals = ApprovalEngine(db_path=":memory:")
    
    # 1. Create a signed grant
    grant = approvals.grant_temporary_approval(
        actor="ops-agent",
        capability="deployment.execute.production",
        environment="production",
        duration_seconds=100.0,
    )
    
    # Check succeeds because the signature is intact
    ok, fetched_grant = approvals.check_approval(
        actor="ops-agent",
        capability_str="deployment.execute.production",
        environment="production",
    )
    assert ok is True
    assert fetched_grant is not None
    assert fetched_grant.metadata.get("signature") is not None
    
    # 2. Simulate manual SQLite database tampering of the capability parameter
    # Update SQLite database directly to tamper with the capability of the grant
    approvals._db.execute(
        "UPDATE approved_grants SET capability = ? WHERE id = ?",
        ("system.root.production", grant.id)
    )
    
    # Check fails (fail-closed!) because capability was changed and signature verification fails!
    ok_tampered, _ = approvals.check_approval(
        actor="ops-agent",
        capability_str="system.root.production",
        environment="production",
    )
    assert ok_tampered is False


def test_break_glass_operational_semantics(caplog) -> None:
    import logging
    approvals = ApprovalEngine(db_path=":memory:")
    
    # Create break-glass emergency grant
    approvals.grant_temporary_approval(
        actor="ops-agent",
        capability="deployment.execute.production",
        environment="production",
        duration_seconds=100.0,
        granted_by="break_glass",
        metadata={"break_glass": True}
    )
    
    # Check generates warning logs
    with caplog.at_level(logging.WARNING):
        ok, _ = approvals.check_approval(
            actor="ops-agent",
            capability_str="deployment.execute.production",
            environment="production",
        )
        assert ok is True
        assert any("BREAK-GLASS: Emergency break-glass authorization activated" in r.message for r in caplog.records)


def test_wildcard_permissiveness_auditing(caplog) -> None:
    import logging
    caps = CapabilitySystem()
    
    with caplog.at_level(logging.WARNING):
        caps.load_policy({
            "allow": ["*.*.*", "system.root.*"],
        })
        
        warnings = [r.message for r in caplog.records]
        assert any("SECURITY WARNING: Overly permissive wildcard policy loaded" in msg for msg in warnings)
        assert any("SECURITY WARNING: Highly sensitive system-level wildcard loaded" in msg for msg in warnings)


def test_audit_chain_covers_runtime_columns(tmp_path: Path) -> None:
    caps = CapabilitySystem()
    caps.load_policy({"allow": ["filesystem.read"]})
    audit = ImmutableAuditTrail(db_path=tmp_path / "audit.db")
    runtime = ActionRuntime(
        capability_system=caps,
        approval_engine=ApprovalEngine(db_path=":memory:"),
        audit_trail=audit,
    )

    event = ActionEvent.create(
        actor="agent",
        action="read",
        resource="filesystem",
        environment="production",
        risk="low",
        payload={"path": "/tmp/report.txt"},
    )
    runtime.execute(event)

    valid_before, errors_before = audit.verify()
    assert valid_before is True
    assert errors_before == []

    audit._db.execute("UPDATE audit_events SET capability = ? WHERE id = 1", ("filesystem.write",))
    valid_after, errors_after = audit.verify()
    assert valid_after is False
    assert any("entry_hash mismatch" in error for error in errors_after)
