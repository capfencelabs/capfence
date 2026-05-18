# Your First Blocked Action

This walkthrough shows what enforcement looks like end-to-end: a policy blocks a dangerous tool call before it reaches the tool.

## Setup

Create `policies/demo.yaml`:

```yaml
deny:
  - capability: shell.execute
    contains: "rm -rf"

allow:
  - capability: shell.execute
```

## Code

```python
from capfence import ActionRuntime, ActionEvent

# 1. Initialize the runtime directly from a policy file
runtime = ActionRuntime.from_policy("policies/demo.yaml")

# This call is safe — it passes
event1 = ActionEvent.create(
    actor="demo-agent",
    action="execute",
    resource="shell",
    environment="production",
    payload={"command": "ls -la /tmp"}
)
verdict1 = runtime.execute(event1)
print(verdict1.authorized)   # True

# This call is dangerous — it is blocked before execution
event2 = ActionEvent.create(
    actor="demo-agent",
    action="execute",
    resource="shell",
    environment="production",
    payload={"command": "rm -rf /var/lib/postgresql"}
)
verdict2 = runtime.execute(event2)
print(verdict2.authorized)   # False
print(verdict2.reason)   # policy_deny
```

## What happens at the framework layer

With a LangChain wrapper, blocked calls raise an exception so the agent cannot proceed:

```python
from capfence import CapFenceTool
from langchain.tools import ShellTool

safe_shell = CapFenceTool(
    tool=ShellTool(),
    agent_id="demo-agent",
    capability="shell.execute",
    policy_path="policies/demo.yaml"
)

# This raises AgentActionBlocked — the shell never runs
safe_shell.run("rm -rf /var/lib/postgresql")
```

```
AgentActionBlocked: Blocked: policy_deny
```

## Checking the audit log

Both the allowed and denied decisions are recorded:

```bash
capfence logs
```

```
timestamp            agent_id      capability      decision  reason
2024-01-15 10:23:01  demo-agent    shell.execute   allow     policy_allow
2024-01-15 10:23:02  demo-agent    shell.execute   deny      policy_deny
```

## Verifying log integrity

```bash
capfence verify --audit-log ./audit.db
✓ Audit chain intact. 2 entries verified.
```

## Next steps

- [Guides](../guides/protect-shell-tools.md) — protect real agent tools
- [Human approval workflows](../guides/require-human-approval.md) — pause for review instead of denying
- [Replay an incident](../guides/replay-an-incident.md) — re-evaluate a past decision
