# CapFence Docs

CapFence is deterministic execution enforcement for AI agents.

It intercepts agent tool calls before execution, evaluates explicit policy, fail-closes unsafe requests, and records decisions for replay.

```text
Agent -> Tool Call -> Policy Evaluation -> Allow / Deny / Approval -> Audit + Replay
```

Prompts are not security boundaries. CapFence removes the LLM from the authorization path.

## Start here

1. Install CapFence.
2. Define one policy.
3. Wrap one dangerous tool.
4. Attempt one blocked action.
5. Replay the decision.

```bash
pip install capfence
```

```yaml
deny:
  - capability: shell.exec.production
    contains: "rm -rf"

allow:
  - capability: shell.exec.readonly
```

```python
from capfence import ActionEvent, ActionRuntime

runtime = ActionRuntime.from_policy("policies/shell.yaml")

event = ActionEvent.create(
    actor="ops-agent",
    resource="shell",
    action="exec",
    environment="production",
    payload={"command": "rm -rf /var/lib/postgresql"},
)

verdict = runtime.execute(event)

if not verdict.authorized:
    raise PermissionError(f"Blocked before execution: {verdict.reason}")
```

## What is implemented today

- Capability-based policy evaluation with explicit `deny`, `require_approval`, and `allow` rules.
- Fail-closed behavior for unmatched capabilities and policy/runtime failures.
- Local approval state for scoped, expiring grants.
- Local audit records with hash chaining for tamper-evidence.
- Replay-oriented CLI and examples for re-evaluating historical decisions against policy.
- Lightweight adapters and examples for common agent/tool boundaries, including MCP.

## What CapFence controls

- `shell.exec` before a process is spawned.
- Filesystem reads and writes before secrets or repo-external paths are touched.
- Database writes and schema changes before the connection executes a query.
- Payment or API calls before money or external state moves.
- MCP tool calls before the upstream server receives the JSON-RPC request.

## What to read

- [First blocked action](getting-started/first-blocked-action.md)
- [Runtime authorization](concepts/runtime-authorization.md)
- [Policy model](concepts/policy-model.md)
- [Fail-closed enforcement](concepts/fail-closed-enforcement.md)
- [Replayability](concepts/replayability.md)
- [Threat model](architecture/threat-model.md)
- [MCP interception model](architecture/mcp-interception-model.md)

## What CapFence is not

CapFence is not an AI governance platform, observability product, orchestration framework, prompt guardrail, AI judge, or compliance dashboard.

Use it as the deterministic authorization layer at the point where agent output becomes execution.
