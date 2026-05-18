# Quickstart

CapFence sits between your AI agent and its tools. It evaluates every tool call against a policy before execution happens.

## 1. Install

```bash
pip install capfence
```

## 2. Write a policy

Create `policies/my_policy.yaml`:

```yaml
deny:
  - capability: filesystem.delete
  - capability: shell.root_access

require_approval:
  - capability: payments.transfer
    amount_gt: 1000

allow:
  - capability: filesystem.read
  - capability: shell.execute
```

## 3. Wrap your tool

### LangChain

```python
from capfence import CapFenceTool
from langchain.tools import ShellTool

safe_shell = CapFenceTool(
    tool=ShellTool(),
    agent_id="my-agent",
    capability="shell.execute",
    policy_path="policies/my_policy.yaml"
)
```

### Direct Runtime API

```python
from capfence import ActionRuntime, ActionEvent

# 1. Initialize the runtime directly from a policy file
runtime = ActionRuntime.from_policy("policies/my_policy.yaml")

# 2. Represent the action as a governed event
event = ActionEvent.create(
    actor="my-agent",
    action="execute",
    resource="shell",
    environment="production",
    risk="medium",
    payload={"command": "ls -la /tmp"}
)

# 3. Enforce the decision
verdict = runtime.execute(event)

if verdict.authorized:
    # execute the tool
    pass
else:
    print(f"Blocked: {verdict.reason}")
```

## 4. Run your agent

Your agent runs normally. CapFence intercepts each tool call:

- **Allowed** calls pass through to the tool.
- **Denied** calls raise `AgentActionBlocked` before the tool runs.
- **Approval-required** calls pause and enter the approval queue.

Every decision is recorded in the local audit log at `./audit.db`.

## 5. Check the audit log

```bash
capfence logs
```

## 6. Verify log integrity

```bash
capfence verify --audit-log ./audit.db
```

## Next steps

- [First policy](first-policy.md) — full policy syntax walkthrough
- [First blocked action](first-blocked-action.md) — observe a denial end-to-end
- [Guides](../guides/protect-shell-tools.md) — real-world protection patterns
