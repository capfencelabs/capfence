# Operational Pattern 01: Payment Threshold Authorization

Payment agents can create real financial side effects. CapFence sits before the payment API and evaluates the requested transfer before money moves.

## Threat

A treasury agent receives adversarial instructions and attempts to transfer corporate funds to an unknown account.

```text
payments.transfer amount=50000 destination=unknown_account
```

## Request

```text
actor: treasury-agent
capability: payments.transfer.production
payload: {"amount": 50000, "destination": "unknown_account"}
environment: production
```

## Policy

```yaml
deny:
  - capability: payments.transfer.production
    destination: unknown_account

require_approval:
  - capability: payments.transfer.production
    amount_gt: 1000

allow:
  - capability: payments.transfer.production
    amount_lte: 1000
```

## Decision

```text
decision: REQUIRE_APPROVAL
reason: amount_threshold_exceeded
tool_invoked: false
```

The payment API does not receive the transfer until a scoped approval exists.

## Replay

```bash
capfence replay audit.jsonl --policy policies/payments.yaml
```

Use replay to test whether a stricter policy would have denied previous transfers to unknown destinations.

## Audit

Record the actor, amount, destination, policy hash, approval state, decision, and replay identifier.

## What CapFence does not solve

CapFence does not replace bank-side controls, payment provider risk scoring, credential scoping, or fraud review. It controls the agent execution path before the payment API is called.
