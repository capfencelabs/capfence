"""Tests for the premium CapFence Redesign Primitives."""

import json
import time

from capfence import (
    ActionEvent,
    ActionRuntime,
    Capability,
    CapabilitySystem,
    ApprovalEngine,
    ImmutableAuditTrail,
    ReplayEngine,
)


class TestCapabilitySystem:
    def test_capability_parsing(self):
        c1 = Capability.parse("github.push.main")
        assert c1.resource == "github"
        assert c1.action == "push"
        assert c1.scope == "main"

        c2 = Capability.parse("filesystem.read")
        assert c2.resource == "filesystem"
        assert c2.action == "read"
        assert c2.scope == "*"

        c3 = Capability.parse("database")
        assert c3.resource == "database"
        assert c3.action == "*"
        assert c3.scope == "*"

    def test_capability_matching(self):
        granted = Capability.parse("github.push.*")
        required_ok = Capability.parse("github.push.main")
        required_fail = Capability.parse("github.pull.main")

        assert granted.matches(required_ok) is True
        assert granted.matches(required_fail) is False

        # Global wildcard
        global_wildcard = Capability.parse("*.*.*")
        assert global_wildcard.matches(required_ok) is True

    def test_capability_system_policies(self):
        policy = {
            "allow": ["filesystem.read.workspace", "github.push.*"],
            "require_approval": ["deployment.execute.production"],
            "deny": ["filesystem.delete.workspace"],
        }
        sys = CapabilitySystem()
        sys.load_policy(policy)

        # Allow checks
        assert sys.evaluate_capability("filesystem.read.workspace") == "allow"
        assert sys.evaluate_capability("github.push.main") == "allow"

        # Deny checks
        assert sys.evaluate_capability("filesystem.delete.workspace") == "deny"

        # Require approval checks
        assert sys.evaluate_capability("deployment.execute.production") == "require_approval"

        # Default deny checks
        assert sys.evaluate_capability("database.write.prod") == "default_deny"


class TestApprovalEngine:
    def test_temporary_expiring_approval(self):
        engine = ApprovalEngine(db_path=":memory:")
        
        # Grant a capability for 2 seconds
        grant = engine.grant_temporary_approval(
            actor="agent-1",
            capability="deployment.execute.production",
            environment="production",
            duration_seconds=2.0,
            granted_by="slack_webhook",
        )
        assert grant.actor == "agent-1"
        assert grant.capability == "deployment.execute.production"

        # Check active approval
        approved, active_grant = engine.check_approval(
            actor="agent-1",
            capability_str="deployment.execute.production",
            environment="production",
        )
        assert approved is True
        assert active_grant is not None
        assert active_grant.id == grant.id

        # Sleep to let it expire
        time.sleep(2.1)

        approved_expired, _ = engine.check_approval(
            actor="agent-1",
            capability_str="deployment.execute.production",
            environment="production",
        )
        assert approved_expired is False

    def test_session_bound_approval(self):
        engine = ApprovalEngine(db_path=":memory:")
        
        # Grant capability for specific session
        grant = engine.grant_session_approval(
            actor="agent-1",
            capability="github.push.main",
            environment="production",
            session_id="session-xyz-123",
        )

        # Fails without session
        approved_no_session, _ = engine.check_approval(
            actor="agent-1",
            capability_str="github.push.main",
            environment="production",
        )
        assert approved_no_session is False

        # Fails with wrong session
        approved_wrong_session, _ = engine.check_approval(
            actor="agent-1",
            capability_str="github.push.main",
            environment="production",
            session_id="session-abc",
        )
        assert approved_wrong_session is False

        # Passes with correct session
        approved_ok, active_grant = engine.check_approval(
            actor="agent-1",
            capability_str="github.push.main",
            environment="production",
            session_id="session-xyz-123",
        )
        assert approved_ok is True
        assert active_grant.id == grant.id

    def test_approval_persistence_survives_reinit(self, tmp_path):
        db_file = tmp_path / "test_approvals.db"
        engine = ApprovalEngine(db_path=db_file)
        
        # Grant a capability
        engine.grant_temporary_approval(
            actor="agent-persist",
            capability="s3.write.bucket-1",
            environment="production",
            duration_seconds=3600.0,
            granted_by="slack_webhook",
        )
        
        # Create second ApprovalEngine pointing to the same path
        engine2 = ApprovalEngine(db_path=db_file)
        
        # Check active approval on second engine
        approved, active_grant = engine2.check_approval(
            actor="agent-persist",
            capability_str="s3.write.bucket-1",
            environment="production",
        )
        assert approved is True
        assert active_grant is not None
        assert active_grant.capability == "s3.write.bucket-1"


class TestActionRuntime:
    def test_runtime_execution_flows(self):
        caps = CapabilitySystem()
        caps.load_policy({
            "allow": ["filesystem.read.*"],
            "require_approval": ["deployment.execute.*"],
        })
        approvals = ApprovalEngine(db_path=":memory:")
        audit = ImmutableAuditTrail()

        runtime = ActionRuntime(
            capability_system=caps,
            approval_engine=approvals,
            audit_trail=audit,
        )

        # 1. Allowed event
        ev_allow = ActionEvent.create(
            actor="ops-agent",
            action="read",
            resource="filesystem",
            environment="development",
        )
        verdict_allow = runtime.execute(ev_allow)
        assert verdict_allow.authorized is True
        assert verdict_allow.decision == "allow"
        assert verdict_allow.reason == "policy_allow"

        # 2. Blocked event (policy require_approval, no active grant)
        ev_require = ActionEvent.create(
            actor="ops-agent",
            action="execute",
            resource="deployment",
            environment="production",
        )
        verdict_require = runtime.execute(ev_require)
        assert verdict_require.authorized is False
        assert verdict_require.decision == "require_approval"
        assert verdict_require.reason.startswith("approval_required:")

        # 3. Allowed after temporary grant approval
        approvals.grant_temporary_approval(
            actor="ops-agent",
            capability="deployment.execute.production",
            environment="production",
            duration_seconds=10.0,
        )
        verdict_approved = runtime.execute(ev_require)
        assert verdict_approved.authorized is True
        assert verdict_approved.decision == "allow"
        assert verdict_approved.reason.startswith("approved_grant:")


class TestReplayEngine:
    def test_incident_trace_replay(self, tmp_path):
        # Create a trace file
        trace_file = tmp_path / "incident.jsonl"
        events = [
            {"capfence_replay_version": "1.0", "checksum": "ignore"},
            {"actor": "coding-agent", "action": "push", "resource": "github", "environment": "production", "risk": "critical", "decision": "pass"},
            {"actor": "ops-agent", "action": "execute", "resource": "deployment", "environment": "production", "risk": "critical", "decision": "fail"},
        ]
        with open(trace_file, "w") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

        # Create policies
        caps = CapabilitySystem()
        caps.load_policy({
            "allow": ["github.push.production"],
        })
        runtime = ActionRuntime(
            capability_system=caps,
            approval_engine=ApprovalEngine(db_path=":memory:"),
            audit_trail=ImmutableAuditTrail(),
        )

        engine = ReplayEngine(runtime=runtime)
        summary = engine.replay_incident(trace_file)

        assert summary.total_events == 2
        # github.push.production allowed
        assert summary.results[0].authorized is True
        # deployment.execute.production defaults to deny
        assert summary.results[1].authorized is False
        
        # SOC2/ISO evidence is produced
        assert summary.compliance_evidence["status"] == "COMPLIANT"
