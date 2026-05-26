# Decision Receipts

Every CapFence decision should be explainable as a receipt.

Example:

```txt
Decision: DENY
Actor: support-agent
Tool: payments.refund
Action: create_refund
Resource: payment:pay_123
Environment: production
Policy: payments/refund-threshold@v1
Reason: amount 2500 exceeds maximum allowed refund amount 500
Tool invoked: false
Audit ID: aud_01
Replay: capfence replay aud_01
```

A decision receipt answers:

- Who requested the action?
- What tool would have executed?
- What resource was targeted?
- Which policy applied?
- Was the tool invoked?
- Can the decision be replayed?
