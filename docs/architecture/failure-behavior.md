# Failure Behavior

CapFence should fail closed when it cannot make an authorization decision.

## Expected failure states

| Failure | Expected behavior |
| --- | --- |
| Missing policy | raises an operational error; caller must treat as blocked |
| Malformed policy | returns a `deny` verdict |
| Unknown capability | returns a `deny` verdict |
| Approval lookup failure | may raise an operational error during execution; caller must treat as blocked |
| Audit write failure | may raise an operational error during execution; caller must treat as blocked |
| Adapter exception before tool invocation | raises an operational error; caller must treat as blocked |

## Why this matters

Agent execution can have external effects. If the authorization layer is uncertain, the safe behavior is to avoid invoking the downstream system.

```text
policy error -> deny verdict or raised error treated as blocked -> tool not called
```

## Operator visibility

Fail-closed behavior should produce an observable error and an audit entry when possible. Silent blocks are hard to debug; silent allows are worse.

## Deployment note

The project is early. Before relying on fail-closed semantics in a production path, test the adapter and persistence configuration you plan to use.
