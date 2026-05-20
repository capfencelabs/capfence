# Failure Behavior

CapFence should fail closed when it cannot make an authorization decision.

## Expected failure states

| Failure | Expected behavior |
| --- | --- |
| Missing policy | deny |
| Malformed policy | deny |
| Unknown capability | deny |
| Approval lookup failure | deny |
| Audit write failure | deny or surface an explicit operational error |
| Adapter exception before tool invocation | deny |

## Why this matters

Agent execution can have external effects. If the authorization layer is uncertain, the safe behavior is to avoid invoking the downstream system.

```text
policy error -> deny -> tool not called
```

## Operator visibility

Fail-closed behavior should produce an observable error and an audit entry when possible. Silent blocks are hard to debug; silent allows are worse.

## Deployment note

The project is early. Before relying on fail-closed semantics in a production path, test the adapter and persistence configuration you plan to use.
