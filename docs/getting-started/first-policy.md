# Your First Policy

A CapFence policy is a YAML file that defines what an agent can do, what it cannot do, and what requires human sign-off.

## Policy structure

```yaml
deny:
  - capability: <capability-name>
    [conditions...]

allow:
  - capability: <capability-name>
    [conditions...]

require_approval:
  - capability: <capability-name>
    [conditions...]

risk_levels:
  low:
    action: allow
  medium:
    action: warn
  high:
    action: require_approval
  critical:
    action: block
```

Rules are evaluated top-to-bottom. The first matching rule wins. If no rule matches, the default behavior is **deny** (fail-closed).

## Example: shell agent policy

```yaml
# policies/shell_agent.yaml

deny:
  - capability: shell.execute
    contains: "rm -rf"
  - capability: shell.execute
    contains: "DROP TABLE"
  - capability: shell.root_access

require_approval:
  - capability: shell.execute
    contains: "systemctl"
  - capability: filesystem.write
    path_prefix: "/etc"

allow:
  - capability: shell.execute
  - capability: filesystem.read
  - capability: filesystem.write
```

## Example: payments agent policy

```yaml
# policies/payments_agent.yaml

deny:
  - capability: payments.transfer
    amount_gt: 50000

require_approval:
  - capability: payments.transfer
    amount_gt: 1000
  - capability: payments.refund
    amount_gt: 500

allow:
  - capability: payments.read
  - capability: payments.transfer
    amount_lte: 1000
```

## Conditions reference

| Condition | Type | Description |
|---|---|---|
| `capability` | string | Exact capability name to match |
| `contains` | string | Matches if the payload contains this substring |
| `amount_gt` | number | Matches if extracted numeric value exceeds threshold |
| `amount_lte` | number | Matches if extracted numeric value is at or below threshold |
| `path_prefix` | string | Matches filesystem paths starting with this prefix |
| `environment` | string | Matches runtime context environment label |
| `user_role` | string | Matches caller role from policy context |

## Injecting runtime context

Policies can evaluate fields from runtime context passed at call time:

```python
safe_tool.run(
    action,
    policy_context={
        "environment": "production",
        "user_role": "engineer",
        "tenant": "acme-corp"
    }
)
```

Then in your policy:

```yaml
require_approval:
  - capability: database.write
    environment: production
```

## Saving and loading policies

Policies are plain YAML files. Point any adapter at a policy file, or pass the policy path during direct gate evaluation:

```python
runtime = ActionRuntime.from_policy("policies/shell_agent.yaml")
event = ActionEvent.create(
    actor="ops-agent",
    action="execute",
    resource="shell",
    environment="production",
    risk="medium",
    payload={"command": "ls -la"}
)
verdict = runtime.execute(event)
```

You can maintain separate policies per agent, environment, or tenant and swap them at runtime.

## Next steps

- [First blocked action](first-blocked-action.md) — see your policy block something
- [Policy schema reference](../reference/policy-schema.md) — complete field reference
