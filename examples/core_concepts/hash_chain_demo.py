"""Example: Hash-chained audit log (Week 7a).

Demonstrates tamper-evident audit logging with SHA-256 chain linkage.
"""

from __future__ import annotations

from capfence.core.runtime import ActionRuntime, ActionEvent
from capfence.core.capabilities import CapabilitySystem, Capability
from capfence.core.approvals import ApprovalEngine
from capfence.core.audit import AuditLogger
from capfence.core.chain import verify_chain_from_rows


def main() -> None:
    # Create an audit logger with hash-chaining enabled
    audit = AuditLogger(db_path=":memory:", sign_entries=False)

    # Configure explicit capability rules
    caps = CapabilitySystem()
    caps.allowed.append(Capability.parse("read_only.read_balance.*"))
    caps.denied.append(Capability.parse("execute.shell.*"))

    # Initialize ActionRuntime canonical engine
    runtime = ActionRuntime(
        capability_system=caps,
        approval_engine=ApprovalEngine(db_path=":memory:"),
        audit_trail=audit,
        mode="enforce",
    )

    # Decision 1: safe read — passes
    event1 = ActionEvent.create(
        actor="agent-1",
        action="read_balance",
        resource="read_only",
        environment="production",
        risk="low",
        account_id="123",
    )
    verdict1 = runtime.execute(event1)
    print(f"Decision 1: {'PASS' if verdict1.authorized else 'BLOCK'} (decision={verdict1.decision})")

    # Decision 2: dangerous execute — blocked
    event2 = ActionEvent.create(
        actor="agent-1",
        action="shell",
        resource="execute",
        environment="production",
        risk="high",
        command="rm -rf /",
    )
    verdict2 = runtime.execute(event2)
    print(f"Decision 2: {'PASS' if verdict2.authorized else 'BLOCK'} (decision={verdict2.decision})")

    # Verify the chain integrity
    rows = audit.get_events_chronological(limit=100)
    valid, errors = verify_chain_from_rows(rows)

    print(f"\nAudit chain verification: {'VALID' if valid else 'INVALID'}")
    if errors:
        for e in errors:
            print(f"  Error: {e}")
    else:
        print(f"  {len(rows)} entries, no tampering detected")

    # Demonstrate tamper detection by manually corrupting a row
    if rows:
        conn = audit._db._connection()
        conn.execute(
            "UPDATE audit_events SET decision = 'tampered' WHERE id = ?",
            (rows[0]["id"],),
        )
        conn.commit()

        rows_after = audit.get_events_chronological(limit=100)
        valid_after, errors_after = verify_chain_from_rows(rows_after)
        print(f"\nAfter tampering entry {rows[0]['id']}:")
        print(f"  Verification: {'VALID' if valid_after else 'INVALID'}")
        for e in errors_after:
            print(f"  Detected: {e}")


if __name__ == "__main__":
    main()
