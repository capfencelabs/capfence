# ActionRuntime & ActionEvent API Reference

`capfence.core.runtime.ActionRuntime` is the canonical, low-latency execution authorization runtime for autonomous systems.

## Constructor

```python
from capfence import ActionRuntime, CapabilitySystem, ApprovalEngine, AuditLogger

runtime = ActionRuntime(
    capability_system=CapabilitySystem(),
    approval_engine=ApprovalEngine(db_path="approvals.db"),
    audit_trail=AuditLogger(db_path="audit.db"),
    mode="enforce",
)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `capability_system` | `CapabilitySystem` | Required | Local declarative policy evaluator. |
| `approval_engine` | `ApprovalEngine` | Required | Human approval queue manager (SQLite backed). |
| `audit_trail` | `AuditLogger` | Required | Verifiable decision logging engine. |
| `mode` | `str` | `"enforce"` | Operation mode (`"enforce"` or deprecated `"observe"`/`"stealth"`). |

---

## Classmethod `ActionRuntime.from_policy()`
Create a pre-configured `ActionRuntime` using default database engines and load a local policy file directly.

```python
runtime = ActionRuntime.from_policy("policies/ops.yaml")
```

---

## `ActionRuntime.execute()`
Evaluates an event against loaded policies and returns a deterministic authorization verdict.

```python
verdict = runtime.execute(event)
```

| Parameter | Type | Description |
|---|---|---|
| `event` | `ActionEvent` | The governed action details to evaluate. |

---

## `ActionEvent`
Represents an action attempting to cross the execution boundary.

### Construct via `ActionEvent.create()`
```python
event = ActionEvent.create(
    actor="deployment-agent",
    action="execute",
    resource="deployment",
    environment="production",
    risk="high",
    payload={"command": "ls -la"},
    metadata={"session_id": "session-123", "require_approval": True}
)
```

### Properties
| Property | Type | Description |
|---|---|---|
| `actor` | `str` | Name of the executing agent or actor (non-empty). |
| `action` | `str` | The operation being performed (non-empty). |
| `resource` | `str` | Target resource namespace (non-empty). |
| `environment` | `str` | Deployment environment label (non-empty). |
| `risk` | `str \| float` | Risk priority string (`"low"`, `"medium"`, `"high"`, `"critical"`) or score. |
| `metadata` | `dict` | Explicitly typed payload metadata (keys must match whitelisted schemas). |

---

## `ExecutionVerdict`
Represents the result returned by `runtime.execute()`.

| Field | Type | Description |
|---|---|---|
| `decision` | `str` | Evaluation outcome (`"allow"`, `"deny"`, `"require_approval"`, or `"default_deny"`). |
| `reason` | `str` | Structured explanation of the decision. |
| `authorized` | `bool` | Convenience helper. `True` if `decision` is `"allow"`. |
| `risk_score` | `float \| None` | Evaluated numeric risk value. |
| `threshold` | `float \| None` | Active risk threshold boundary. |
| `latency_ms` | `float \| None` | Evaluated execution runtime duration. |
