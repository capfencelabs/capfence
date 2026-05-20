# Approval Lifecycle

Approvals are scoped exceptions for actions that policy marks as `require_approval`. They are not a replacement for explicit policy; they are a temporary grant checked during evaluation.

## Lifecycle

```text
ActionEvent
  -> policy matches require_approval
  -> runtime checks approval store
  -> active matching grant?
       yes -> allow and audit
       no  -> require_approval and audit
```

## Grant shape

A grant should be scoped to the smallest useful boundary:

- actor
- capability
- environment
- duration
- reviewer
- reason

```python
approval_engine.grant_capability(
    actor="treasury-agent",
    capability="payments.transfer.production",
    granted_by="operator-01",
    duration_seconds=900,
)
```

## Failure behavior

If approval lookup fails, the runtime should fail closed. A missing or unreachable approval store must not silently allow execution.

## Operational guidance

Use approval for exceptional execution, not routine access. If a capability is expected to run frequently, encode the safe envelope in policy and reserve approval for threshold crossings.
