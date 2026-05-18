# Fail-Closed Enforcement

Fail-closed means that when CapFence cannot reach a decision — due to a policy error, missing configuration, or internal fault — it blocks the action rather than allowing it through.

## The default position

In a fail-open system, uncertainty means "allow." In a fail-closed system, uncertainty means "deny."

CapFence is fail-closed by default. If the runtime raises an unhandled exception, the framework adapter catches it and blocks the tool call. The agent receives an error. The tool never runs.

```
policy error → runtime exception → AgentActionBlocked raised → tool not invoked
```

## Why fail-closed matters for agents

AI agents can make hundreds of tool calls across a session. A single gap in enforcement — one call that slips through while the runtime is misconfigured — can have real consequences: a deleted file, a transferred payment, a leaked secret.

Fail-closed guarantees that gaps in policy are visible as errors, not silent passes.

## What triggers a fail-closed block

- Policy file is missing or malformed
- Policy rule references an unknown condition field
- Runtime raises an internal error during evaluation
- Audit log write fails (depending on configuration)

## Fail-closed in practice

```python
from capfence import ActionRuntime, ActionEvent

# 1. Loading a missing policy file fails closed automatically
runtime = ActionRuntime.from_policy("policies/missing_file.yaml")

event = ActionEvent.create(
    actor="agent-1",
    action="execute",
    resource="shell",
    environment="production",
    payload={"command": "echo hello"}
)

# 2. Evaluation returns a default deny verdict
verdict = runtime.execute(event)
# verdict.authorized == False
# verdict.decision == "default_deny"
```

The tool is blocked. The error is logged. The agent is informed.

## Configuring strict mode

By default, CapFence blocks unmatched capabilities (no rule matches → deny). This is the strictest posture. You can explicitly add an allow-all fallback if needed, but this is not recommended for production:

```yaml
# Not recommended in production
allow:
  - capability: "*"
```

The correct approach is to enumerate capabilities your agent uses and write explicit rules for each one.

## Related concepts

- [Runtime authorization](runtime-authorization.md)
- [Policy model](policy-model.md)
- [Threat model](../architecture/threat-model.md)
