"""Tamper-evidence demo for CapFence's hash chain audit log.

Demonstrates that the audit log is tamper-evident: any modification to a
recorded entry causes chain verification to fail with a precise error pointing
to the corrupted row.

Run:
    python examples/core_concepts/tamper_demo.py

Expected output:
    ✓ Chain VALID (6 entries, 0 errors)
    — Tampering with entry 3 (changing decision from 'pass' to 'fail')...
    ✗ Chain INVALID: 2 error(s) detected
      - Entry 3: entry_hash mismatch ...
      - Entry 4: prev_hash mismatch ...
    ✓ Tamper correctly detected at insertion point and all downstream entries
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from capfence.core.audit import AuditLogger
from capfence.core.runtime import ActionRuntime, ActionEvent
from capfence.core.capabilities import CapabilitySystem, Capability
from capfence.core.approvals import ApprovalEngine


def _populate_log(db_path: Path) -> AuditLogger:
    """Record six realistic ActionRuntime decisions to the audit log."""
    audit = AuditLogger(db_path=db_path, sign_entries=False)
    
    # Configure capability system to allow all actions for the demo
    caps = CapabilitySystem()
    caps.allowed.append(Capability.parse("*.*.*"))
    
    runtime = ActionRuntime(
        capability_system=caps,
        approval_engine=ApprovalEngine(db_path=":memory:"),
        audit_trail=audit
    )

    scenarios = [
        ("agent-payments-1", "check_balance",       "balance_inquiry",     {"account": "acct_123"}),
        ("agent-payments-1", "list_transactions",   "transaction_history", {"account": "acct_123", "limit": 20}),
        ("agent-payments-1", "initiate_payment",    "payment_initiation",  {"to": "vendor_42", "amount": 250.00}),
        ("agent-payments-1", "large_wire_transfer", "high_value_transfer", {"amount": 48000, "currency": "USD"}),
        ("agent-payments-1", "initiate_payment",    "payment_initiation",  {"to": "vendor_42", "amount": 500.00}),
        ("agent-payments-1", "check_balance",       "balance_inquiry",     {"account": "acct_123"}),
    ]

    for agent_id, task_context, risk_category, payload in scenarios:
        event = ActionEvent.create(
            actor=agent_id,
            action=task_context,
            resource=risk_category,
            environment="production",
            risk="low",
            payload=payload,
        )
        runtime.execute(event)

    return audit


def _verify_and_print(audit: AuditLogger, label: str) -> tuple[bool, list[str]]:
    valid, errors = audit.verify()
    icon = "✓" if valid else "✗"
    events = audit.get_events(limit=1000)
    count = len(events)
    if valid:
        print(f"{icon} Chain VALID ({count} entries, 0 errors)  [{label}]")
    else:
        print(f"{icon} Chain INVALID: {len(errors)} error(s) detected  [{label}]")
        for e in errors:
            print(f"    - {e}")
    return valid, errors


def main() -> None:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    try:
        print("=== CapFence Tamper-Evidence Demo ===\n")

        # 1. Populate
        print("Step 1 — Recording 6 ActionRuntime decisions to audit log...")
        audit = _populate_log(db_path)
        events = audit.get_events_chronological(limit=100)
        print(f"  Recorded {len(events)} entries.")
        print()

        # 2. Verify clean chain
        print("Step 2 — Verifying chain integrity (no tampering yet):")
        _verify_and_print(audit, "baseline")
        print()

        # 3. Show entries
        print("Step 3 — Current chain entries:")
        print(f"  {'ID':<4} {'Agent':<22} {'Task':<25} {'Decision':<8} {'entry_hash (prefix)'}")
        print("  " + "-" * 80)
        for ev in events:
            print(
                f"  {ev['id']:<4} {ev['agent_id']:<22} {ev['task_context']:<25} "
                f"{ev['decision']:<8} {ev['entry_hash'][:20]}..."
            )
        print()

        # 4. Tamper with entry 3 directly in SQLite
        target_id = events[2]["id"]
        original_decision = events[2]["decision"]
        tampered_decision = "fail" if original_decision == "pass" else "pass"

        print(f"Step 4 — Tampering: changing entry id={target_id} decision "
              f"'{original_decision}' → '{tampered_decision}' directly in SQLite...")
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE audit_events SET decision = ? WHERE id = ?",
            (tampered_decision, target_id),
        )
        conn.commit()
        conn.close()
        print("  (Simulating an attacker who modified the database directly.)")
        print()

        # 5. Re-open and verify — must detect tampering
        print("Step 5 — Re-verifying chain after tamper:")
        audit2 = AuditLogger(db_path=db_path)
        valid, errors = _verify_and_print(audit2, "post-tamper")
        print()

        # 6. Explain the failure
        if not valid:
            print("Step 6 — Failure analysis:")
            print(f"  CapFence detected {len(errors)} chain break(s).")
            print(f"  Entry {target_id}: the stored entry_hash was computed from the original content.")
            print("  After the decision field was changed, re-hashing the content produces a different")
            print("  digest — the stored hash no longer matches the stored content.")
            print()
            print("  This is the expected behavior of a tamper-evident chain:")
            print("  every entry's hash commits to its entire content. Changing even a single byte")
            print("  in any field causes verification to fail on that entry.")
            print()
            print("  An attacker who wants to cover their tracks would also need to:")
            print("    1. Recompute the entry_hash for the modified entry.")
            print("    2. Update the prev_hash of every subsequent entry.")
            print("    3. Recompute all downstream entry_hashes.")
            print("  This is computationally feasible — the protection is append-only storage")
            print("  (immutable object store, WORM drive, blockchain anchor) which prevents")
            print("  step 1 from being written back. The hash chain is the evidence record;")
            print("  it requires a trustworthy write path to be a complete solution.")
        else:
            print("  ERROR: tampering was NOT detected — chain logic has a bug.")

        print()

        # 7. Restore and verify
        print("Step 7 — Restoring original value and re-verifying:")
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE audit_events SET decision = ? WHERE id = ?",
            (original_decision, target_id),
        )
        conn.commit()
        conn.close()
        audit3 = AuditLogger(db_path=db_path)
        _verify_and_print(audit3, "post-restore")

        print()
        print("=== Demo complete. ===")
        print()
        print("To run this on a real audit log:")
        print("  capfence verify --audit-log path/to/audit.db")

    finally:
        db_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
