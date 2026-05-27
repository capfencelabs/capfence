# CapFence

CapFence is the authorization gateway between AI agents and real-world side effects.

Models may propose actions. CapFence decides whether those actions are allowed before execution.

Use CapFence when agents can touch shell commands, databases, filesystems, payment APIs, internal APIs, SaaS admin tools, or MCP servers.

<p align="center">
  <a href="https://pypi.org/project/capfence/"><img src="https://img.shields.io/pypi/v/capfence?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/capfence/"><img src="https://img.shields.io/pypi/pyversions/capfence" alt="Python versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <a href="https://github.com/capfencelabs/capfence/actions/workflows/ci.yml"><img src="https://github.com/capfencelabs/capfence/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
</p>

```txt
Agent -> Proposed action -> CapFence -> Gated executor -> Tool
```

Denied actions do not reach the downstream tool.

Prompts are not security boundaries. CapFence removes the LLM from the authorization path.

## First Blocked Action

An ops agent proposes:

```bash
rm -rf /var/lib/postgresql
```

CapFence returns:

```txt
Decision: DENY
Reason: destructive production filesystem operation
Tool invoked: false
Replay: capfence replay audit_sample.jsonl --policy policy.yaml
```

## Install

```bash
pip install capfence
```

## Try It Locally

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

## Security Model

CapFence protects the gated tool path.

Recommended architecture:

```txt
Agent -> Proposed action -> CapFence -> Gated executor -> Tool
```

The agent should not hold raw downstream credentials. The executor owns credentials and invokes the tool only after CapFence returns `allow`.

CapFence is not effective if the agent can call downstream tools directly with raw credentials.

CapFence does not replace sandboxing, secrets management, network controls, IAM, or database-native permissions.

## Why Authorization, Not Guardrails?

Prompt guardrails influence what the model says. CapFence controls what the agent is allowed to do.

The security question is not only:

> Did the model intend something safe?

The operational question is:

> Is this actor authorized to perform this side effect on this resource in this environment?

CapFence is built for that boundary.

## How CapFence Is Different

| Category | What it controls | Weakness | CapFence difference |
| --- | --- | --- | --- |
| Prompt guardrails | Model text | Soft boundary | CapFence controls execution |
| LLM judges | Generated content | Probabilistic | CapFence uses deterministic policy |
| Observability | Past behavior | After the fact | CapFence blocks before execution |
| Sandboxes | Process/environment | Not business authorization | CapFence evaluates action semantics |
| IAM | Service identity | Too coarse for agent intent | CapFence authorizes each proposed action |
| Runtime contracts | Agent behavior patterns | Broad or abstract | CapFence focuses on concrete side effects |

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

- [Agent authority model](docs/concepts/agent-authority-model.md)
- [Action authorization](docs/concepts/action-authorization.md)
- [Runtime authorization](docs/concepts/runtime-authorization.md)
- [Policy model](docs/concepts/policy-model.md)
- [Decision receipts](docs/audit/decision-receipts.md)
- [Credential placement](docs/security/credential-placement.md)
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
