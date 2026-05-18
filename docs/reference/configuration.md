# Configuration Reference

CapFence is configured through constructor parameters and policy files. There is no required global configuration file.

## ActionRuntime configuration

```python
from capfence import ActionRuntime, CapabilitySystem, ApprovalEngine, AuditLogger

runtime = ActionRuntime(
    capability_system=CapabilitySystem(),
    approval_engine=ApprovalEngine(db_path="approvals.db"),
    audit_trail=AuditLogger(db_path="audit.db"),
    mode="enforce",
)
```

| Parameter | Description |
|---|---|
| `capability_system` | Local declarative policy evaluator. |
| `approval_engine` | Human approval queue manager (SQLite backed). |
| `audit_trail` | Verifiable decision logging engine. |
| `mode` | Operation mode (`"enforce"` or deprecated `"observe"`/`"stealth"`). |

## Adapter configuration

```python
from capfence import CapFenceTool, ActionRuntime

runtime = ActionRuntime.from_policy("policies/shell.yaml")

safe_tool = CapFenceTool(
    tool=my_tool,
    agent_id="my-agent",
    capability="shell.execute",
    policy_path="policies/shell.yaml",
    gate=runtime,
)
```

Adapters add framework-specific wrapping around the same execution runtime primitive.

## Policy file location

Policy files can live anywhere on disk. A common layout is:

```text
policies/
  production.yaml
  staging.yaml
  agents/
    finance-agent.yaml
    ops-agent.yaml
```

## Audit database location

Configure a path for persistent, verifiable audit logs:

```python
from capfence import AuditLogger

audit = AuditLogger(db_path="/var/log/myapp/capfence.db")
```

## Approval timeout

Set approval timeout in the policy file:

```yaml
approval_timeout_seconds: 3600
```

## Logging

CapFence uses the standard Python `logging` module under the `capfence` logger name.

```python
import logging

logging.getLogger("capfence").setLevel(logging.WARNING)
```
