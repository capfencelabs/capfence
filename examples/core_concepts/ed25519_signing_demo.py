"""Example: signed audit entries.

Demonstrates cryptographic signing of ActionRuntime audit decisions.
"""

from capfence.core.approvals import ApprovalEngine
from capfence.core.audit import AuditLogger
from capfence.core.capabilities import CapabilitySystem
from capfence.core.keys import generate_keypair, load_keypair, verify_entry
from capfence.core.runtime import ActionEvent, ActionRuntime


def main() -> None:
    pub_b64, priv_b64 = generate_keypair()
    print("Generated audit signing keypair")
    print(f"  Public key:  {pub_b64[:20]}...")
    print(f"  Private key: {priv_b64[:20]}...")

    caps = CapabilitySystem()
    caps.load_policy({"allow": ["payment.transfer"]})
    audit = AuditLogger(db_path=":memory:", sign_entries=True)
    runtime = ActionRuntime(
        capability_system=caps,
        approval_engine=ApprovalEngine(db_path=":memory:"),
        audit_trail=audit,
    )

    event = ActionEvent.create(
        actor="agent-1",
        action="transfer",
        resource="payment",
        environment="production",
        risk="high",
        payload={"amount": 100.0, "to": "vendor_123"},
    )
    verdict = runtime.execute(event)
    print(f"\nDecision: {'PASS' if verdict.authorized else 'BLOCK'}")

    rows = audit.get_events_chronological(limit=1)
    if rows:
        entry = rows[0]
        print("\nAudit entry:")
        print(f"  ID:        {entry['id']}")
        print(f"  Decision:  {entry['decision']}")
        print(f"  Signature: {entry['signature'][:40]}..." if entry.get("signature") else "  Signature: None")

        sign_fields = {
            "agent_id": entry["agent_id"],
            "task_context": entry["task_context"],
            "risk_category": entry["risk_category"],
            "decision": entry["decision"],
            "risk_score": entry.get("risk_score"),
            "threshold": entry.get("threshold"),
            "payload_hash": entry.get("payload_hash"),
            "reason": entry.get("reason"),
            "latency_ms": entry.get("latency_ms"),
            "timestamp": entry["timestamp"],
            "actor": entry.get("actor"),
            "action": entry.get("action"),
            "resource": entry.get("resource"),
            "environment": entry.get("environment"),
            "capability": entry.get("capability"),
            "approval_state": entry.get("approval_state"),
            "policy_decision": entry.get("policy_decision"),
            "execution_result": entry.get("execution_result"),
            "metadata_json": entry.get("metadata_json"),
            "prev_hash": entry.get("prev_hash", ""),
            "entry_hash": entry.get("entry_hash", ""),
        }
        is_valid = verify_entry(sign_fields, entry["signature"], pub_b64)
        print(f"\nSignature verification: {'VALID' if is_valid else 'INVALID'}")

    loaded = load_keypair()
    if loaded:
        print(f"\nLoaded existing keypair: {loaded[0][:20]}...")


if __name__ == "__main__":
    main()
