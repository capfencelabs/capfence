# CapFence Docs

CapFence is the authorization gateway between AI agents and real-world side effects.

Models may propose actions. CapFence decides whether those actions are allowed before execution.

```txt
Agent -> Proposed action -> CapFence -> Gated executor -> Tool
```

Denied actions do not reach the downstream tool.

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
- Starter policy packs for shell, filesystem/MCP, SQL, payments, and Kubernetes boundaries.
- Policy fixture testing, explain output, and policy diff commands.

## What CapFence controls

- `shell.exec` before a process is spawned.
- Filesystem reads and writes before secrets or repo-external paths are touched.
- Database writes and schema changes before the connection executes a query.
- Payment or API calls before money or external state moves.
- MCP tool calls before the upstream server receives the JSON-RPC request.

## What to read

- [First blocked action](getting-started/first-blocked-action.md)
- [Agent authority model](concepts/agent-authority-model.md)
- [Action authorization](concepts/action-authorization.md)
- [Runtime authorization](concepts/runtime-authorization.md)
- [Policy model](concepts/policy-model.md)
- [Decision receipts](audit/decision-receipts.md)
- [Credential placement](security/credential-placement.md)
- [Fail-closed enforcement](concepts/fail-closed-enforcement.md)
- [Replayability](concepts/replayability.md)
- [Threat model](architecture/threat-model.md)
- [MCP interception model](architecture/mcp-interception-model.md)
- [Why not sandboxing, OPA, or prompt guardrails?](concepts/why-not-sandboxing-opa-guardrails.md)

## What CapFence is not

CapFence is not an AI governance platform, observability product, orchestration framework, prompt guardrail, AI judge, sandbox, IAM system, secrets manager, or compliance dashboard.

Use it as the deterministic authorization layer at the point where agent output becomes execution.

## Public beta status

CapFence is pre-1.0 public beta infrastructure. The local YAML policy runtime is the most mature surface. Framework adapters, starter policy packs, MCP interception, external policy backends, and release hardening are available for production pilots only after environment-specific validation.
