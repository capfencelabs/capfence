# Migration Guide: Gate to ActionRuntime

`Gate` is deprecated in CapFence v0.8.0 and will be removed in v1.0. All downstream applications should transition to `ActionRuntime`, the canonical execution authorization runtime.

## Key Changes
- The `Gate` API evaluated risk against legacy heuristic scoring systems.
- The `ActionRuntime` API evaluates explicit, capability-based policies (`resource.action.scope`) deterministically, with built-in isolated replay support and human-in-the-loop approval escalation.

---

## Migration Example

### Before: Using `Gate`
```python
from capfence import Gate

# Initialize gate
gate = Gate(policy_path="policies/ops.yaml")

# Evaluate tool invocation
result = gate.evaluate(
    agent_id="agent-1",
    task_context="execute",
    risk_category="shell",
    payload={"command": "rm -rf /"},
    capability="shell.execute.*"
)

if not result.passed:
    print(f"Blocked call: {result.reason}")
```

### After: Using `ActionRuntime`
```python
from capfence import ActionRuntime, ActionEvent

# Initialize ActionRuntime canonical engine
runtime = ActionRuntime.from_policy("policies/ops.yaml")

# Construct execution event
event = ActionEvent.create(
    actor="agent-1",
    action="execute",
    resource="shell",
    environment="production",
    risk="high",
    command="rm -rf /"
)

# Deterministic execution authorization check
verdict = runtime.execute(event)

if not verdict.authorized:
    print(f"Blocked call: {verdict.reason}")
```
