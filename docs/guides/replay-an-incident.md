# Replay an Incident

When something goes wrong — an agent made a call it shouldn't have, or was blocked unexpectedly — CapFence lets you replay the exact decision to understand what happened and why.

## Finding the relevant entry

```bash
# Search by agent ID
capfence logs --agent finance-agent --json

# Review recent events
capfence logs --audit-log audit.db --limit 100
```

Note the `entry_hash` or `payload_hash` from the JSON output.

## Viewing a trace

```bash
capfence trace a1b2c3d4
```

Output:

```
Trace ID:     a1b2c3d4
Timestamp:    2024-01-15 10:23:01 UTC
Agent ID:     finance-agent
Capability:   payments.transfer
Payload hash: sha256:e3b0c4...

Risk evaluation:
  Score: 82 / 100
  Keywords matched: ["transfer", "external_account"]
  Threshold: 70

Policy rules evaluated:
  Rule 1 (deny, amount_gt=50000): not matched (amount=2500)
  Rule 2 (require_approval, amount_gt=1000): MATCHED (amount=2500)

Decision:     require_approval
Reason:       threshold_exceeded
Policy file:  policies/payments_agent.yaml (sha256:c8d1f2...)
```

## Replaying against a different policy

If you've updated your policy and want to see how the incident would have been handled:

```bash
# Replay the captured trace
capfence replay incident.jsonl --policy policies/new_policy.yaml
```

This replays the captured payloads against the candidate policy and prints deterministic replay output.

## Replaying a batch of entries

Replay an entire time window against a policy:

```bash
capfence replay daily.jsonl --policy policies/new_policy.yaml
```

This is useful for validating a policy change before deploying it.

## Verifying log integrity before replay

Always verify the audit chain before relying on replay results:

```bash
capfence verify --audit-log ./audit.db
✓ Audit chain intact. 1,284 entries verified.
```

If the chain is broken, the replay cannot be trusted.

## Related concepts

- [Replayability](../concepts/replayability.md)
- [Audit chain](../concepts/audit-chain.md)
- [FlowTracer API](../reference/flowtracer-api.md)
