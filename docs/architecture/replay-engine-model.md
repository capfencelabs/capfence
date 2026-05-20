# Replay Engine Model

The replay engine re-evaluates recorded execution requests against a selected policy.

It is built for incident review and policy change validation. It is not model simulation.

```text
recorded ActionEvent + policy file -> replay verdict + decision diff
```

## Lifecycle

1. An agent requests a tool call.
2. CapFence records the structured execution input and decision.
3. An operator selects the original policy or a candidate policy.
4. Replay evaluates the recorded request against that policy.
5. The report shows whether the decision changed.

## Before and after example

```text
Recorded request:
  actor: finance-agent
  capability: payments.transfer.production
  payload: {"amount": 5000, "destination": "unknown"}

Policy v1:
  amount_gt: 1000 -> require_approval

Policy v2:
  unknown_destination -> deny

Replay result:
  REQUIRE_APPROVAL -> DENY
```

## Useful outputs

| Output | Use |
|---|---|
| Decision diff | See which historical calls change behavior. |
| Matched rule | Explain why a decision happened. |
| Payload hash | Tie replay output back to audit evidence. |
| Policy hash | Prove which policy was evaluated. |

## Determinism

Given the same recorded event and the same policy, evaluation should produce the same decision.

Replay does not reconstruct hidden model reasoning. It re-runs policy against recorded execution context.

## Limits

Replay cannot recover fields the adapter failed to record.

Replay also cannot prove that the downstream system executed correctly after an allow decision. It proves the authorization decision for the request CapFence saw.
