# Replay Engine Model

Replay re-evaluates recorded execution decisions against policy. It is useful for incident review, policy simulation, and before/after comparisons.

## What replay does

Replay loads recorded action context and runs policy evaluation again:

```text
recorded ActionEvent + selected policy -> new verdict
```

This helps answer operational questions:

- Would a proposed policy have blocked this action?
- Which historical requests change from `allow` to `deny`?
- Why did a request require approval?
- Did a policy update broaden access unexpectedly?

## Before and after example

```text
Recorded request:
  capability: payments.transfer.production
  payload: {"amount": 5000}

Policy v1:
  amount_gt: 1000 -> require_approval

Policy v2:
  amount_gt: 2500 -> deny

Replay result:
  decision changed from require_approval to deny
```

## Determinism

Given the same recorded event and same policy, evaluation should produce the same decision. Replay does not re-run the model or reconstruct hidden chain-of-thought. It re-runs policy against recorded execution context.

## Limits

Replay quality depends on what was recorded. If raw payload storage is disabled or an adapter omits important fields, replay cannot recover that missing context.
