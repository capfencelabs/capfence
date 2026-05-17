# CapFence

CapFence is a deterministic trusted execution runtime for autonomous AI systems.

It sits between an agent and its tools, evaluates each attempted tool action against capability policy, and blocks unauthorized operations before execution.

```text
Agent -> CapFence Runtime -> System / API
              |
              +-- [Allow] -> Execution
              +-- [Deny]  -> Fail-Closed Block
              +-- [Require Approval] -> Pre-Authorized Scopes
```

CapFence is built for teams shipping autonomous agents that interface with high-risk operations: shell execution, production databases, payment APIs, local filesystems, MCP servers, SaaS admin endpoints, and cloud infrastructure.

---

## Why It Exists

Prompt guardrails and model instructions are not an execution boundary. A prompt can be bypassed, misinterpreted, or manipulated. 

CapFence treats autonomous tool execution like secure infrastructure authorization: **explicit capability policies, deterministic decisions, tamper-evident audit trails, dynamic pre-approvals, and complete fail-closed behavior.**

---

## Core Capabilities

- **Deterministic Enforcement**: Policy-as-code evaluations mapped to `resource.action.scope` wildcards.
- **Zero LLM Latency**: Pure-Python capability matching ensures sub-millisecond interlocks without any cloud APIs.
- **Pluggable Persistence**: Decoupled storage using [BaseDBEngine](concepts/runtime-authorization.md), supporting local SQLite WAL files or high-throughput PostgreSQL pools.
- **Pre-Authorizations**: Manage expiring temporary and session-bound capability credentials dynamically.
- **Cryptographic Audit Chain**: Logs decisions in a tamper-evident hash chain with Ed25519 asymmetric signatures.
- **Trace Replay & Incident Simulation**: Replay historical trace files offline to safely test policy changes and generate compliance evidence.
- **Static Scanning & CI Checks**: Scan Python codebases to catch and block ungated tool registrations during CI/CD.

---

## Five-Minute Path

### 1. Install

```bash
pip install capfence
```

### 2. Create a Capability Policy (`policies/ops.yaml`)

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

### 3. Evaluate and Enforce

```python
from capfence import ActionEvent, ActionRuntime, CapabilitySystem, ApprovalEngine, ImmutableAuditTrail

# 1. Initialize low-latency runtime components
caps = CapabilitySystem()
caps.load_policy("policies/ops.yaml")

runtime = ActionRuntime(
    capability_system=caps,
    approval_engine=ApprovalEngine(),
    audit_trail=ImmutableAuditTrail(),
)

# 2. Formulate the governed event
event = ActionEvent.create(
    actor="hotfix-agent",
    action="delete",
    resource="filesystem.workspace",
    environment="production",
    risk="high",
    command="rm -rf /var/lib/postgresql"
)

# 3. Deterministic enforcement
verdict = runtime.execute(event)

if not verdict.authorized:
    raise PermissionError(f"Action blocked by CapFence: {verdict.reason}")
```

---

## Common Workflows

- Start with [Installation](getting-started/installation.md).
- Run the [Quickstart](getting-started/quickstart.md).
- Write [your first policy](getting-started/first-policy.md).
- See [your first blocked action](getting-started/first-blocked-action.md).
- Use [recipes](recipes/index.md) for copy-paste policy patterns.
- Roll out safely with [observe mode](guides/observe-mode-rollout.md).
- Protect [shell tools](guides/protect-shell-tools.md), [payment agents](guides/protect-payment-agents.md), and [MCP servers](guides/secure-mcp-servers.md).
- Use [CI/CD enforcement](guides/ci-cd-enforcement.md) to catch ungated tools.
- Replay an incident with [trace replay](guides/replay-an-incident.md).
- Check the [compatibility matrix](integrations/compatibility.md) before wiring adapters.
- Run the [demo walkthrough](examples/demo-walkthrough.md).

---

## Project Status

CapFence is open infrastructure for trusted autonomous execution.
- Docs: https://capfence.dev/
- PyPI: https://pypi.org/project/capfence/
- Repository: https://github.com/capfencelabs/capfence
