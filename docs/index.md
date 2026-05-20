# CapFence

> **Execution authorization infrastructure for autonomous systems.**

CapFence is an early runtime authorization layer for autonomous agents and tool-using systems. It sits between an agent runtime and downstream systems, evaluates each attempted action against explicit capability policy, and returns one of three decisions: `allow`, `deny`, or `require_approval`.

The core thesis is simple:

> Prompt instructions are not execution boundaries.

```text
Agent runtime
  |
  | ActionEvent(actor, resource, action, payload, environment)
  v
CapFence authorization layer
  |
  | policy evaluation + approval lookup + audit write
  v
Downstream system
  shell | database | MCP tool | API | payment gateway
```

CapFence is not an observability tool, prompt guardrail, eval framework, orchestration framework, tracing platform, or moderation system. It is focused on deterministic execution authorization before a tool or downstream system is invoked.

---

## What is implemented today

- Capability-based policy evaluation with explicit `deny`, `require_approval`, and `allow` rules.
- Fail-closed default behavior for unmatched capabilities and policy/runtime errors.
- Local approval state for scoped, expiring grants.
- Local audit records with hash chaining for tamper-evidence.
- Replay-oriented CLI and examples for re-evaluating historical decisions against policy.
- Lightweight adapters and examples for common agent/tool boundaries, including MCP.

Some areas are intentionally early:

- Framework adapters are thin wrappers around public tool interfaces.
- Database examples classify coarse request categories; they are not a complete SQL firewall.
- Multi-agent lineage examples use caller metadata and policy context; they are experimental patterns, not a mature distributed identity system.
- Audit hash chaining detects changes to the recorded log; it does not replace external key management, centralized SIEM, or full forensic controls.

---

## Five-minute path

### 1. Install

```bash
pip install capfence
```

### 2. Create a capability policy

```yaml
deny:
  - capability: filesystem.delete.workspace
    contains: "rm -rf"

require_approval:
  - capability: payment.execute.high_value
    amount_gt: 1000

allow:
  - capability: filesystem.read.workspace
  - capability: payment.execute.high_value
    amount_lte: 1000
```

### 3. Evaluate before execution

```python
from capfence import ActionEvent, ActionRuntime

runtime = ActionRuntime.from_policy("policies/ops.yaml")

event = ActionEvent.create(
    actor="hotfix-agent",
    action="delete",
    resource="filesystem.workspace",
    environment="production",
    risk="high",
    payload={"command": "rm -rf /var/lib/postgresql"},
)

verdict = runtime.execute(event)

if not verdict.authorized:
    raise PermissionError(f"Action blocked by CapFence: {verdict.reason}")
```

---

## Core docs

- [Runtime authorization](concepts/runtime-authorization.md)
- [Policy model](concepts/policy-model.md)
- [Fail-closed enforcement](concepts/fail-closed-enforcement.md)
- [Replayability](concepts/replayability.md)
- [Audit chain](concepts/audit-chain.md)
- [Policy evaluation model](architecture/policy-evaluation-model.md)
- [Approval lifecycle](architecture/approval-lifecycle.md)
- [Replay engine model](architecture/replay-engine-model.md)
- [MCP interception model](architecture/mcp-interception-model.md)
- [Failure behavior](architecture/failure-behavior.md)

## Operational patterns

- [Protect shell tools](guides/protect-shell-tools.md)
- [Protect payment agents](guides/protect-payment-agents.md)
- [Secure MCP servers](guides/secure-mcp-servers.md)
- [Replay an incident](guides/replay-an-incident.md)
- [Observe-mode rollout](guides/observe-mode-rollout.md)

## Project status

CapFence is early OSS infrastructure. Review the implementation, policy model, and examples before using it in high-risk execution paths.

- Docs: https://capfence.dev/
- PyPI: https://pypi.org/project/capfence/
- Repository: https://github.com/capfencelabs/capfence
