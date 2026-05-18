# Custom Framework Integration

If you are using a framework without a built-in adapter, call the CapFence ActionRuntime API directly before executing a tool.

## Direct Runtime Usage

```python
from capfence import ActionRuntime, ActionEvent

# 1. Initialize ActionRuntime canonical engine
runtime = ActionRuntime.from_policy("policies/my_policy.yaml")

payload = {"command": "ls /tmp"}

# 2. Formulate the governed event
event = ActionEvent.create(
    actor="my-agent",
    action="execute",
    resource="shell",
    environment="production",
    payload=payload
)

# 3. Deterministic execution authorization check
verdict = runtime.execute(event)

if verdict.authorized:
    output = run_tool(payload)
else:
    raise RuntimeError(f"Blocked: {verdict.reason}")
```

## Wrapper Class

```python
from typing import Any
from capfence import ActionRuntime, ActionEvent
from capfence.errors import AgentActionBlocked

class GatedTool:
    def __init__(self, tool: Any, agent_id: str, capability: str, policy_path: str):
        self.tool = tool
        self.agent_id = agent_id
        self.capability = capability
        self.policy_path = policy_path
        self.runtime = ActionRuntime.from_policy(policy_path)

    def run(self, payload: dict, policy_context: dict | None = None) -> Any:
        # Construct the execution event dynamically
        event = ActionEvent.create(
            actor=self.agent_id,
            action="execute",
            resource=self.capability,
            environment=policy_context.get("environment", "production") if policy_context else "production",
            payload=payload,
            metadata=policy_context or {}
        )

        verdict = self.runtime.execute(event)

        if not verdict.authorized:
            raise AgentActionBlocked(
                detail=f"{self.capability} blocked: {verdict.reason}",
                # Map verdict metadata
                gate_result=verdict,
            )

        return self.tool.run(payload)
```

## Related Reference

- [ActionRuntime & ActionEvent API reference](../reference/gate-api.md)
- [Policy schema](../reference/policy-schema.md)
