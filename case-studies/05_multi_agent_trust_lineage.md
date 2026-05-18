# Case Study 05: Multi-Agent Collaboration & Trust Lineage

## 1. Executive Summary

### The Challenge
Modern enterprise AI systems are designed as multi-agent collaboration graphs (using LangGraph, CrewAI, or AutoGen). In these systems, a public-facing routing agent receives raw inputs and routes tasks to highly privileged, internal action agents (DevOps, billing, data access). This introduces **propagation vulnerabilities**:
1. **Secondary Prompt Injection**: An attacker injects the public agent, which does not execute the injection itself but propagates the malicious payload to a privileged backend agent which executes it.
2. **Context Poisoning**: A low-trust agent reads untrusted web data and passes corrupted context to an executive agent, triggering unauthorized tool calls.
3. **Identity Spoofing**: A compromised node attempts to invoke backend capabilities by pretending to act on behalf of a highly privileged internal system.

### The CapFence Solution
CapFence introduces **Trust Lineage Enforcement**. Privileged tools do not just authorize the immediate caller; they evaluate the full execution lineage (which agents touched the transaction) and the associated trust scores. Using localized verification, CapFence blocks tool execution if any low-trust or unverified node is found in the event transit chain.

---

## 2. Declarative Policy (`policies/multi_agent_policy.yaml`)

```yaml
# policies/multi_agent_policy.yaml
policy_name: Multi-Agent Trust Propagation Policy
version: 1.0.0

deny:
  # Block privileged billing actions if initiated by low-trust public nodes
  - capability: billing.charge
    user_role: unverified_public
  - capability: system.restart
    environment: staging

require_approval:
  # Force approvals if a high-risk operation has mixed-trust lineage
  - capability: database.write
    user_role: mixed_trust

allow:
  # Permits full access only if the lineage is 100% verified internal agents
  - capability: database.read
  - capability: billing.charge
    user_role: internal_operator
```

---

## 3. Reference Implementation

Below is a complete, self-contained Python program demonstrating multi-agent node state transitions, lineage tracking, and capability authorization based on caller identity context.

```python
import os
from capfence import ActionRuntime, ActionEvent

class BillingSystem:
    """Mock billing gateway charging customer credit cards."""
    def charge_card(self, amount: float) -> str:
        print(f"💳 [BILLING] Successfully charged credit card for ${amount:.2f}.")
        return "charge_success"

def execute_multi_agent_flow(
    nodes_traversed: list[str],
    payload: dict,
    runtime: ActionRuntime,
    billing: BillingSystem
) -> None:
    """Simulates a multi-agent task runner evaluating execution lineage."""
    print(f"\nEvaluating execution transit chain: {' -> '.join(nodes_traversed)}")
    
    # 1. Evaluate trust level based on nodes traversed in lineage
    if "untrusted_public_agent" in nodes_traversed:
        user_role = "unverified_public"
    elif "marketing_analytics_agent" in nodes_traversed:
        user_role = "mixed_trust"
    else:
        user_role = "internal_operator"
        
    # 2. Build our governed action event, encapsulating lineage context
    event = ActionEvent.create(
        actor=nodes_traversed[-1],  # The immediate calling agent
        action="charge",
        resource="billing",
        environment="production",
        risk="high",
        payload=payload,
        metadata={"user_role": user_role, "lineage": nodes_traversed}
    )
    
    # 3. Authorize via CapFence ActionRuntime
    verdict = runtime.execute(event)
    print(f"Verdict: Authorized={verdict.authorized} | Decision={verdict.decision} | AssignedRole={user_role}")
    
    if verdict.authorized:
        billing.charge_card(payload["amount"])
    else:
        print(f"🛡️ [SECURITY REJECTION] Denied billing charge of ${payload['amount']}! Reason: Lineage trust violation.")

def run_multi_agent_demo():
    policy_path = "policies/multi_agent_policy.yaml"
    
    # Write our multi-agent trust policy
    os.makedirs("policies", exist_ok=True)
    with open(policy_path, "w") as f:
        f.write("""
deny:
  - capability: billing.charge
    user_role: "unverified_public"
allow:
  - capability: billing.charge
    user_role: "internal_operator"
""")

    runtime = ActionRuntime.from_policy(policy_path)
    billing = BillingSystem()
    print("🚀 Multi-Agent Trust Guard initialized successfully.")

    # ----------------------------------------------------
    # Scenario 1: Trusted Internal Flow (Internal Agent -> Billing)
    # ----------------------------------------------------
    print("\n--- Scenario 1: Trusted Internal Execution Lineage ---")
    execute_multi_agent_flow(
        nodes_traversed=["sales_agent", "order_processing_agent"],
        payload={"amount": 49.99},
        runtime=runtime,
        billing=billing
    )

    # ----------------------------------------------------
    # Scenario 2: High-Risk Hijacked Flow (Public Agent -> Internal Agent -> Billing)
    # ----------------------------------------------------
    print("\n--- Scenario 2: Hijacked/Untrusted Egress Lineage Blocked ---")
    execute_multi_agent_flow(
        nodes_traversed=["untrusted_public_agent", "order_processing_agent"],
        payload={"amount": 999.99},
        runtime=runtime,
        billing=billing
    )

if __name__ == "__main__":
    run_multi_agent_demo()
```

---

## 4. Security & Compliance Analysis

### Lineage Security Profile
1. **End-to-End Context Tracking**: Traditional gateway firewalls only inspect the final API dispatch. By tracking the complete agent graph lineage (`nodes_traversed`) and passing it in metadata to CapFence, we prevent "man-in-the-middle" agent attacks and backend execution hijacks.
2. **Deterministic Role Mapping**: Because roles are mapped deterministically inside the Python wrapper according to the node execution path (rather than trusting the model to describe its role), the authorization boundaries are completely immune to prompt injection bypasses.
3. **Forensic Audit Readiness**: The SHA-256 chained log records the entire traversal lineage, providing complete system-level visibility into exactly which agents were involved in any authorized or blocked transactions.
