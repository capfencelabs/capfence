# Replayability

Replay is how CapFence turns historical agent execution into testable policy evidence.

CapFence does not rerun the agent. It reruns deterministic policy evaluation over recorded execution input.

```text
recorded request + selected policy -> replay decision
```

## What is recorded

Every useful replay record should preserve:

- Actor
- Capability
- Environment
- Payload hash
- Optional raw payload
- Policy identity
- Matched rule
- Decision and reason
- Timestamp

## What replay answers

| Operator question | Replay answer |
|---|---|
| Why did this call run? | Shows the matched policy rule and decision trace. |
| Would a stricter policy have blocked it? | Re-evaluates the same request against the candidate policy. |
| Which recent requests would change decision? | Produces a before/after diff across historical traffic. |
| Did a policy update broaden access? | Flags requests that move from `deny` to `allow`. |

## Example

```text
Recorded request:
  actor: analytics-agent
  capability: database.query.production
  payload: DELETE FROM customers

Original policy:
  database.write.production -> require_approval

Candidate policy:
  contains DELETE FROM -> deny

Replay result:
  REQUIRE_APPROVAL -> DENY
```

## CLI

```bash
capfence replay audit.jsonl --policy policies/production.yaml
```

## Determinism property

Given the same recorded request and the same policy, CapFence should produce the same decision.

That is the useful security property: replay is not another model judgment. It is the same authorization function run over preserved execution input.

## Limits

Replay quality depends on capture quality. If the adapter omits important fields or raw payload storage is disabled, replay cannot recover missing context.

Replay also does not prove the downstream system behaved correctly. It proves what CapFence would decide for a recorded request and policy.
