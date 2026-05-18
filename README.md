# CapFence

> **Execution authorization infrastructure for autonomous systems.**

AI agents are non-deterministic. Real-world execution must not be.

---

<p align="center">
  <a href="https://pypi.org/project/capfence/"><img src="https://img.shields.io/pypi/v/capfence?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/capfence/"><img src="https://img.shields.io/pypi/pyversions/capfence" alt="Python versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <a href="https://github.com/capfencelabs/capfence/actions/workflows/ci.yml"><img src="https://github.com/capfencelabs/capfence/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
</p>

CapFence sits between autonomous systems and privileged execution targets (APIs, databases, filesystems, and gateways). It evaluates agent actions against declarative, capability-based policies—allowing, blocking, or queuing actions for approval.

It operates as a **policy enforcement layer and verifiable audit log**, bringing the control of IAM and transaction gateways to autonomous agent runtimes.

```text
Agent SDK ──> CapFence Runtime ──> Target System
                   │
                   ├── [Allow]    ──> Safe Execution
                   ├── [Deny]     ──> Blocked
                   └── [Approval] ──> Temporary / Expiring Grant
```

---

## Why CapFence

When autonomous agents call tools that modify cloud infrastructure, query databases, or execute payments, **prompts are not security boundaries.** A prompt can be bypassed, manipulated, or drift under model updates.

CapFence introduces an independent enforcement boundary:
* **Decoupled Access Control:** Policy logic is isolated from the LLM and evaluated locally using a fast capability engine.
* **Fail-Closed by Default:** If policy validation or audit logging fails, the action is blocked.
* **Tamper-Evident Audit Trails:** Every decision is committed to a hash-chained, verifiable audit trail to prevent retroactive log alterations.

---

## 10-Second Example

### 1. Define Capability Policies (`policies/ops.yaml`)
Establish strict, resource-action-scope access limits. Unmatched capabilities default to deny.

```yaml
policy_name: Production Security Policy
version: 2.0.0

allow:
  - filesystem.read.workspace

require_approval:
  - payment.transfer.*
  - deployment.execute.production

deny:
  - filesystem.delete.workspace
  - shell.execute.*
```

### 2. Enforce at the Runtime Boundary
Initialize CapFence and evaluate actions before execution:

```python
from capfence import ActionRuntime, ActionEvent

# 1. Initialize the runtime directly from a policy file
runtime = ActionRuntime.from_policy("policies/ops.yaml")

# 2. Represent the action as a governed event
event = ActionEvent.create(
    actor="deployment-agent",
    action="execute",
    resource="deployment",
    environment="production"
)

# 3. Enforce the decision
verdict = runtime.execute(event)

if not verdict.authorized:
    raise PermissionError(f"Action blocked by CapFence: {verdict.reason}")
```

---

## Policy Simulation & Incident Replay

The `ReplayEngine` allows you to dry-run policy changes and reconstruct past execution traces.

```python
from capfence import ReplayEngine

# Replay historical traces against a new candidate policy to validate safety
engine = ReplayEngine()
summary = engine.simulate_policy(
    trace_path="traces/incident_log.jsonl",
    policy_path="policies/ops_v2.yaml"
)

print(f"Total Replayed: {summary.total_events} | Blocked: {summary.blocked}")
```

* **Incident Reconstruction:** Re-evaluate exactly what would have occurred under a historical event trace.
* **Policy Validation:** Prevent regressions by testing candidate policy changes against real transaction logs before deployment.

---

## Command Line Interface

CapFence integrates directly into standard CI/CD and operations workflows.

### Grant Temporary Pre-Authorizations
Grant temporary, expiring capabilities to an active agent:
```bash
# Grant 10-minute push access to a hotfix agent
capfence grant --actor hotfix-agent --capability github.push.main --duration 600
```

### Dry-Run Trace Simulations
Replay execution logs against a candidate policy:
```bash
capfence replay traces/agent_trace.jsonl --policy policies/ops_v2.yaml
```

### Verify Audit Log Integrity
Verify that audit database entries have not been modified:
```bash
capfence verify --audit-log audit.db
```

### Codebase Scanning
Scan Python projects to ensure all tools are gated by CapFence:
```bash
capfence check ./src --fail-on-ungated
```

---

## Operational Scope

CapFence enforces runtime policy boundaries. It does not replace:
* **Process Sandboxing:** Always run agents inside isolated runtimes (Docker, gVisor).
* **Least-Privilege Infrastructure:** Cloud IAM policies and database access credentials must remain strictly locked down.
* **Network Isolation:** Restrict network egress to prevent unauthorized public connections.

---

## Project Info
* **Documentation:** Configuration details are in the [docs/](docs/) directory.
* **PyPI:** https://pypi.org/project/capfence/
* **Repository:** https://github.com/capfencelabs/capfence

---

MIT License | Built by [CapFence Labs](https://github.com/capfencelabs)
