# Policy Evaluation Model

CapFence evaluates an attempted action as a deterministic policy decision. The runtime does not ask the model whether the action is safe. It evaluates structured execution context supplied by the adapter or direct caller.

## Input model

An authorization request is represented as an `ActionEvent`:

```python
event = ActionEvent.create(
    actor="ops-agent",
    resource="shell",
    action="execute",
    environment="production",
    risk="high",
    payload={"command": "rm -rf /var/lib/postgresql"},
)
```

The policy engine maps this to a capability such as:

```text
shell.execute.production
```

Rules may also inspect payload fields such as command text, amount, path, environment, or adapter-provided metadata.

## Evaluation order

Rules are evaluated in a fixed order:

1. `deny`
2. `require_approval`
3. `allow`
4. default deny

The first matching rule determines the decision. If no rule matches, CapFence denies by default.

```yaml
deny:
  - capability: shell.execute
    contains: "rm -rf"

require_approval:
  - capability: payments.transfer
    amount_gt: 1000

allow:
  - capability: shell.execute
    contains: "kubectl get"
```

## Decision output

The runtime returns a verdict:

```text
allow             downstream call may proceed
deny              downstream call must not run
require_approval  call is blocked unless a matching active grant exists
```

Adapters are expected to treat `deny` and unresolved `require_approval` as non-execution states.

## Boundaries

The policy engine is deterministic, but it only sees the fields supplied to it. If an adapter fails to include relevant context, policy cannot evaluate that context. Treat adapter design as part of the trust boundary.
