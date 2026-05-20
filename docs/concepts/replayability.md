# Replayability

CapFence can re-evaluate any past enforcement decision against the current policy. This lets you understand why a decision was made, test policy changes against real historical traffic, and reproduce incidents deterministically.

## How replay works

Every audit log entry captures the full context of a gate evaluation:

- The agent ID
- The capability
- The payload (via hash and optional raw storage)
- The policy that was in effect
- The decision and reason

The replay engine loads this context and runs it through the gate again, producing a new decision trace.

## CLI replay

```bash
# View a specific audit entry or payload hash
capfence trace <entry_hash>

# Replay from an exported trace file
capfence replay trace.jsonl
```

## What replay is useful for

**Incident investigation**: Something unexpected happened — an agent made a call that should have been blocked, or was blocked unexpectedly. Replay shows you exactly what the gate saw and why it decided what it did.

**Policy change validation**: Before deploying a new policy, replay recent audit log entries against it. See what would have been allowed or denied differently without running live traffic.

**Compliance reporting**: Auditors need to know what controls were in place at a given point in time and that they functioned correctly. Replay provides deterministic proof.

## Trace output format

```
Trace ID:     a1b2c3d4
Timestamp:    2024-01-15 10:23:01 UTC
Agent ID:     finance-agent-prod
Capability:   payments.transfer
Payload hash: sha256:e3b0c4...

Risk evaluation:
  Score: 82 / 100
  Keywords matched: ["transfer", "production_account"]
  Threshold: 70

Policy rules evaluated:
  Rule 1 (deny, amount_gt=50000): not matched
  Rule 2 (require_approval, amount_gt=1000): MATCHED

Decision: require_approval
Reason:   threshold_exceeded
```

## Determinism property

Given the same payload and the same policy, the gate always produces the same decision. This is the property that makes replay useful: you are not re-running a probabilistic model, you are re-running a deterministic function.

## Related concepts

- [Audit chain](audit-chain.md)
- [Replay an incident guide](../guides/replay-an-incident.md)
- [FlowTracer API reference](../reference/flowtracer-api.md)
