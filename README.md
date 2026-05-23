# CapFence

Deterministic execution authorization for AI agent side effects.

CapFence intercepts agent tool calls before execution, evaluates explicit policy, fail-closes unsafe requests, and records decisions for replay. Models may propose actions. CapFence authorizes side effects.

Prompts are not security boundaries. CapFence removes the LLM from the authorization path.

<p align="center">
  <a href="https://pypi.org/project/capfence/"><img src="https://img.shields.io/pypi/v/capfence?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/capfence/"><img src="https://img.shields.io/pypi/pyversions/capfence" alt="Python versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <a href="https://github.com/capfencelabs/capfence/actions/workflows/ci.yml"><img src="https://github.com/capfencelabs/capfence/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
</p>

```text
Agent -> Tool Call -> CapFence Policy -> Allow / Deny / Approval -> Audit + Replay
```

## What Happens At Execution Time

1. An agent requests a tool call.
2. CapFence receives the capability, actor, payload, and environment.
3. Policy returns `allow`, `deny`, or `require_approval`.
4. Unsafe requests are blocked before the downstream system is invoked.
5. The decision is recorded for audit and deterministic replay.

## Install

```bash
pip install capfence
```

## First Blocked Action

Define a policy:

```yaml
deny:
  - capability: shell.exec.production
    contains: "rm -rf"

allow:
  - capability: shell.exec.readonly
```

Evaluate before execution:

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

Expected result:

```text
decision: DENY
reason: policy_deny
tool_invoked: false
```

Replay the decision:

```bash
capfence replay audit.jsonl --policy policies/shell.yaml
```

Replay output:

```text
Recorded: shell.exec.production
Original: DENY
Replayed: DENY
Changed:  false
```

## Use CapFence For

- `shell.exec` boundaries before a process is spawned.
- MCP tool authorization before the upstream server receives a request.
- Filesystem scope enforcement before secrets or repo-external paths are read.
- Database write and schema-change controls before queries execute.
- Payment or API action thresholds before external state changes.

## CapFence Is Not

- An AI governance platform.
- An observability product.
- An orchestration framework.
- A prompt guardrail.
- An AI judge.
- A compliance dashboard.

## Core Docs

- [Runtime authorization](docs/concepts/runtime-authorization.md)
- [Policy model](docs/concepts/policy-model.md)
- [Fail-closed enforcement](docs/concepts/fail-closed-enforcement.md)
- [Replayability](docs/concepts/replayability.md)
- [Threat model](docs/architecture/threat-model.md)
- [MCP interception model](docs/architecture/mcp-interception-model.md)

## Status

CapFence is pre-1.0 public beta infrastructure. The core local YAML policy runtime is intended for production pilots, while framework adapters, policy packs, external policy backends, and release automation should be validated in your environment before high-risk use.

CapFence controls the gated tool path. It does not replace sandboxing, secrets management, network segmentation, downstream IAM, or database-native controls.

| Capability | Maturity |
| --- | --- |
| Local YAML policy evaluation | Beta |
| Audit hash chaining and replay | Beta |
| LangChain, LangGraph, CrewAI, OpenAI Agents SDK adapters | Beta |
| MCP, PydanticAI, LlamaIndex, AutoGen adapters | Experimental |
| Starter policy packs and OPA backend path | Experimental |

- Docs: https://capfence.dev/
- PyPI: https://pypi.org/project/capfence/
- Repository: https://github.com/capfencelabs/capfence
