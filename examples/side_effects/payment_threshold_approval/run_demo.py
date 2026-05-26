from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

HERE = Path(__file__).resolve().parent


def main() -> None:
    from capfence import ActionEvent, ActionRuntime

    payload = {
        "amount": 2500,
        "currency": "USD",
        "merchant_id": "unknown",
        "idempotency_key": "refund_001",
    }
    runtime = ActionRuntime.from_policy(HERE / "policy.yaml")
    event = ActionEvent.create(
        actor="support-agent",
        action="create_refund",
        resource="payment:pay_123",
        environment="production",
        risk="high",
        capability="payments.refund",
        payload=payload,
    )
    verdict = runtime.execute(event)
    reason = "amount exceeds maximum refund limit and merchant is not approved"
    audit = {
        "audit_id": "aud_payment_001",
        "actor": "support-agent",
        "tool": "payments.refund",
        "action": "create_refund",
        "resource": "payment:pay_123",
        "environment": "production",
        "decision": verdict.decision,
        "reason": reason,
        "tool_invoked": verdict.authorized,
        "payload": payload,
    }
    (HERE / "audit_sample.jsonl").write_text(json.dumps(audit, separators=(",", ":")) + "\n")
    print("requested: payments.refund")
    print("amount: 2500 USD")
    print("merchant_id: unknown")
    print(f"decision: {verdict.decision.upper()}")
    print(f"reason: {reason}")
    print(f"tool_invoked: {str(verdict.authorized).lower()}")


if __name__ == "__main__":
    main()
