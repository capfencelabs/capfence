"""Example: local telemetry-style decision metrics.

CapFence is local-first. This example shows how to summarize audit decisions
without sending raw payloads anywhere.
"""

from capfence import ActionEvent, ActionRuntime, ApprovalEngine, AuditLogger, CapabilitySystem


def main() -> None:
    caps = CapabilitySystem()
    caps.load_policy({"allow": ["filesystem.read"], "deny": ["shell.execute"]})
    audit = AuditLogger(db_path=":memory:")
    runtime = ActionRuntime(
        capability_system=caps,
        approval_engine=ApprovalEngine(db_path=":memory:"),
        audit_trail=audit,
    )

    events = [
        ActionEvent.create(
            actor="demo-agent",
            action="read",
            resource="filesystem",
            risk="low",
            payload={"path": "/tmp/report.txt"},
        ),
        ActionEvent.create(
            actor="demo-agent",
            action="execute",
            resource="shell",
            risk="critical",
            payload={"command": "rm -rf /tmp/cache"},
        ),
    ]
    for event in events:
        runtime.execute(event)

    rows = audit.get_events(limit=100)
    allowed = sum(1 for row in rows if row["decision"] == "pass")
    blocked = sum(1 for row in rows if row["decision"] == "fail")

    print("Local Decision Metrics")
    print("=" * 40)
    print(f"Total decisions: {len(rows)}")
    print(f"Allowed:         {allowed}")
    print(f"Blocked:         {blocked}")
    print("Raw payloads remain local in the audit database.")


if __name__ == "__main__":
    main()
