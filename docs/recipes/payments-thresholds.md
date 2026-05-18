# Protect Payments With Thresholds

## Policy

```yaml
deny:
  - capability: payments.transfer
    amount_gt: 50000

require_approval:
  - capability: payments.transfer
    amount_gt: 1000

allow:
  - capability: payments.transfer
    amount_lte: 1000
```

## Integration

```python
from capfence import ActionRuntime, ActionEvent

# 1. Initialize ActionRuntime canonical engine
runtime = ActionRuntime.from_policy("policies/payments.yaml")

# 2. Formulate the governed event
event = ActionEvent.create(
    actor="payments-agent",
    action="transfer",
    resource="payments",
    environment="production",
    payload={"amount": 5000}
)

# 3. Deterministic execution authorization check
verdict = runtime.execute(event)
```

## Expected result

- Transfers over $50,000 are blocked.
- Transfers between $1,000 and $50,000 require approval.
- Transfers at or below $1,000 are allowed.
