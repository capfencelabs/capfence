# Payment Threshold Approval

This demo shows CapFence treating payments as business authorization, not only technical filtering.

## Scenario

A support agent proposes a refund.

Rules:

```txt
refund <= $100: allow
refund $100-$500: require approval
refund > $500: deny
missing idempotency key: deny
unknown merchant: deny
```

## Run

```bash
python3 run_demo.py
```
