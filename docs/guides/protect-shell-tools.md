# Protect Shell Tools

Shell access is one of the highest-risk capabilities an agent can have. A single `rm -rf`, `curl | bash`, or `chmod 777` can cause irreversible damage. This guide shows how to gate shell tools with CapFence.

## Basic shell policy

```yaml
# policies/shell_agent.yaml

deny:
  - capability: shell.execute
    contains: "rm -rf"
  - capability: shell.execute
    contains: "curl | bash"
  - capability: shell.execute
    contains: "wget | sh"
  - capability: shell.execute
    contains: "chmod 777"
  - capability: shell.execute
    contains: "> /dev/null 2>&1 &"
  - capability: shell.root_access

require_approval:
  - capability: shell.execute
    contains: "systemctl"
  - capability: shell.execute
    contains: "apt-get install"
  - capability: shell.execute
    contains: "pip install"
  - capability: filesystem.write
    path_prefix: "/etc"
  - capability: filesystem.write
    path_prefix: "/usr"

allow:
  - capability: shell.execute
  - capability: filesystem.read
```

## LangChain integration

```python
from capfence import CapFenceTool
from langchain.tools import ShellTool

safe_shell = CapFenceTool(
    tool=ShellTool(),
    agent_id="ops-agent",
    capability="shell.execute",
    policy_path="policies/shell_agent.yaml"
)

# Use safe_shell wherever you'd use ShellTool
tools = [safe_shell]
```

## Direct runtime integration

```python
import subprocess
from capfence import ActionRuntime, ActionEvent

runtime = ActionRuntime.from_policy("policies/shell_agent.yaml")

def safe_run(command: str, agent_id: str) -> str:
    event = ActionEvent.create(
        actor=agent_id,
        action="execute",
        resource="shell",
        environment="production",
        payload={"command": command}
    )
    verdict = runtime.execute(event)
    if not verdict.authorized:
        raise PermissionError(f"Blocked: {verdict.reason}")
    return subprocess.check_output(command, shell=True, text=True)
```

## What to watch in the audit log

After running your agent, review decisions:

```bash
capfence logs --audit-log audit.db --json
```

Use these findings to refine your policy: add explicit `deny` rules for patterns you see, and tighten `require_approval` thresholds.

## Scanning existing codebases

Before adding CapFence, identify which shell tools are currently ungated:

```bash
capfence check ./src --framework langchain
```

This reports tools that are exposed to an agent without a CapFence wrapper.

## Related guides

- [CI/CD enforcement](ci-cd-enforcement.md) — block deploys when ungated shell tools are detected
- [Observe mode rollout](observe-mode-rollout.md) — log without blocking while you tune your policy
