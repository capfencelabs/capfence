"""Tests for semantic hardening and execution-alignment constraints.

Validates ActionEvent validation, JSON serializability, Capability regex parsing, and isolated ReplayEngine.
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path
from tempfile import NamedTemporaryFile

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

    with pytest.raises(ValueError, match="risk score must be a float between 0.0 and 1.0"):
        ActionEvent(actor="agent", action="read", resource="fs", environment="prod", risk=1.5)

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
