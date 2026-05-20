# Operational Pattern 01: Payment Threshold Authorization

## 1. Executive Summary

### The Challenge
Financial platforms are deploying autonomous AI agents to handle invoice matching, customer account updates, and automated payments. However, Large Language Models (LLMs) are inherently non-deterministic. A single prompt injection, adversarial input, or model hallucination can cause:
1. **Silent Fund Exfiltration**: An attacker tricks the agent into transferring corporate funds to a malicious account.
2. **Operational Overdraft**: The model hallucinates payment quantities (e.g., executing a $10,000 refund instead of $100).
3. **Compliance Breaches**: Unapproved transactions violating internal fiduciary thresholds and AML guidelines.

### The CapFence Pattern
CapFence can sit between the agent workflow and the payment gateway API. In this reference implementation, payment requests are evaluated against local capability policy, and requests above configured thresholds require an explicit approval grant before execution.

---

## 2. Declarative Policy (`policies/fintech_policy.yaml`)

```yaml
# policies/fintech_policy.yaml
policy_name: Corporate Treasury & Transfer Policy
version: 1.0.0

# Strict Default-Deny: Unmatched capabilities fail-closed.
deny:
  - capability: payments.transfer
    amount_gt: 10000.0 # Absolute limit for automated operations
  - capability: payments.transfer
    environment: staging
    amount_gt: 50.0    # Sandbox safety check

require_approval:
  - capability: payments.transfer
    amount_gt: 500.0   # Human sign-off required above this threshold
  - capability: payments.refund
    amount_gt: 100.0

allow:
  - capability: payments.transfer
    amount_lte: 500.0  # Automated execution permitted
  - capability: payments.read
```

---

## 3. Reference Implementation

Here is a self-contained Python application demonstrating transfer checks, approval queue escalation, operator override, and transaction logging.

```python
import os
import time
from capfence import ActionRuntime, ActionEvent

def simulate_payment_gateway(account: str, amount: float) -> str:
    """Mock gateway executing the real bank transfer."""
    print(f"💰 [BANK GATEWAY] Successfully transferred ${amount:.2f} to {account}.")
    return f"tx_bank_{int(time.time())}"

def run_fintech_guard_demo():
    # 1. Initialize the CapFence runtime using our declarative policy
    policy_path = "policies/fintech_policy.yaml"
    
    # Let's ensure a mock policy file exists for this demonstration
    os.makedirs("policies", exist_ok=True)
    with open(policy_path, "w") as f:
        f.write("""
deny:
  - capability: payments.transfer
    amount_gt: 10000.0
require_approval:
  - capability: payments.transfer
    amount_gt: 500.0
allow:
  - capability: payments.transfer
    amount_lte: 500.0
""")

    # Initialize the runtime with dedicated file-backed DB engines
    runtime = ActionRuntime.from_policy(policy_path)
    print("🚀 CapFence ActionRuntime initialized successfully.")

    # ----------------------------------------------------
    # Transaction 1: Safe Automated Transfer ($120.00)
    # ----------------------------------------------------
    print("\n--- Scenario 1: Safe Automated Transfer ---")
    event_safe = ActionEvent.create(
        actor="treasury-agent",
        action="transfer",
        resource="payments",
        environment="production",
        risk="low",
        payload={"amount": 120.0, "destination": "vendor-corp-123"}
    )
    
    verdict_safe = runtime.execute(event_safe)
    print(f"Verdict: Authorized={verdict_safe.authorized} | Decision={verdict_safe.decision}")
    
    if verdict_safe.authorized:
        simulate_payment_gateway(
            account=event_safe.payload["destination"],
            amount=event_safe.payload["amount"]
        )
    else:
        print(f"❌ Blocked: {verdict_safe.reason}")

    # ----------------------------------------------------
    # Transaction 2: Dangerous Over-Limit Attempt ($15,000.00)
    # ----------------------------------------------------
    print("\n--- Scenario 2: Dangerous Over-Limit Block ---")
    event_dangerous = ActionEvent.create(
        actor="treasury-agent",
        action="transfer",
        resource="payments",
        environment="production",
        risk="critical",
        payload={"amount": 15000.0, "destination": "malicious-attacker-789"}
    )
    
    verdict_dangerous = runtime.execute(event_dangerous)
    print(f"Verdict: Authorized={verdict_dangerous.authorized} | Decision={verdict_dangerous.decision} | Reason={verdict_dangerous.reason}")
    
    if verdict_dangerous.authorized:
        simulate_payment_gateway(
            account=event_dangerous.payload["destination"],
            amount=event_dangerous.payload["amount"]
        )
    else:
        print(f"🛡️ [SECURITY ACTION] Blocked exfiltration attempt of ${event_dangerous.payload['amount']}!")

    # ----------------------------------------------------
    # Transaction 3: Escalated Human Approval ($2,500.00)
    # ----------------------------------------------------
    print("\n--- Scenario 3: Human Approval Escalation ---")
    event_approval = ActionEvent.create(
        actor="treasury-agent",
        action="transfer",
        resource="payments",
        environment="production",
        risk="high",
        payload={"amount": 2500.0, "destination": "strategic-partner-456"}
    )
    
    verdict_approval = runtime.execute(event_approval)
    print(f"Verdict: Authorized={verdict_approval.authorized} | Decision={verdict_approval.decision} | ApprovalID={verdict_approval.approval_id}")
    
    if verdict_approval.decision == "require_approval":
        print(f"⏳ Transaction escalated to human queue. Ticket ID: {verdict_approval.approval_id}")
        
        # Simulate a secure operator approving the transaction in the database
        print("👤 [OPERATOR OFFICE] Reviewing invoice matching ticket...")
        time.sleep(1)
        
        # Grant a session-bound override for the specific capability
        approval_engine = runtime._approval_engine
        approval_engine.grant_capability(
            actor="treasury-agent",
            capability="payments.transfer.production",
            granted_by="admin-user-01",
            duration_seconds=30  # Active for a 30-second window
        )
        print("✅ [OPERATOR OFFICE] Approved! Temporary capability granted.")
        
        # 4. Re-evaluate the transaction with the active operator grant
        verdict_retry = runtime.execute(event_approval)
        print(f"Retry Verdict: Authorized={verdict_retry.authorized} | Decision={verdict_retry.decision}")
        
        if verdict_retry.authorized:
            simulate_payment_gateway(
                account=event_approval.payload["destination"],
                amount=event_approval.payload["amount"]
            )
        else:
            print("❌ Still Blocked.")

if __name__ == "__main__":
    run_fintech_guard_demo()
```

---

## 4. Operational Notes

### Deterministic Isolation
1. **Prompt-independent decision**: The evaluation uses structured tool arguments such as `amount`; it does not rely on a model's statement that a transfer is safe.
2. **Audit support**: Decisions can be recorded in the local audit log for replay and review.
3. **Fail-closed posture**: Missing policy or runtime errors should block rather than allow the transfer path.
