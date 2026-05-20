# Enforcement Flow

CapFence enforces policy at the final boundary before a tool executes.

```text
Agent -> Tool call -> Capability mapping -> Policy evaluation -> Decision -> Audit + Replay
```

## What happens at execution time

1. The agent requests a tool call.
2. The adapter converts the call into structured execution input.
3. CapFence evaluates capability policy without asking the model.
4. The runtime returns `allow`, `deny`, or `require_approval`.
5. The downstream tool is invoked only when the decision is `allow`.
6. The request and decision are recorded for audit and replay.

## Execution input

| Field | Example | Why it matters |
|---|---|---|
| Actor | `ops-agent` | Identifies the requesting system. |
| Capability | `shell.exec.production` | The policy target. |
| Payload | `rm -rf /var/lib/postgresql` | The requested side effect. |
| Environment | `production` | Separates dev from high-risk paths. |
| Approval state | `grant_expired` | Determines whether approval-gated calls can proceed. |

## Decision behavior

| Decision | Runtime behavior |
|---|---|
| `allow` | The tool call is forwarded to the downstream system. |
| `require_approval` | Execution pauses until a scoped approval grant exists. |
| `deny` | The tool is not invoked. The agent receives a blocked response. |

## What does not happen

- The LLM is not asked whether its own action is safe.
- A denied request is not forwarded to the shell, database, API, payment gateway, or MCP server.
- Missing policy does not silently allow execution.

The enforcement path is intentionally narrow: convert request, evaluate policy, return decision, record evidence.
