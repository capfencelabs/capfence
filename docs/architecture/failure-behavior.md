# Failure Behavior

CapFence should fail closed when it cannot make an authorization decision.

Agent tool execution can mutate infrastructure, delete data, exfiltrate secrets, or move money. If the authorization layer is uncertain, the safe behavior is to avoid invoking the downstream system.

```text
uncertain authorization -> deny verdict or raised error treated as blocked -> tool not called
```

## Expected failure states

| Failure | Expected behavior |
|---|---|
| Missing policy | Raise an operational error; caller must treat as blocked |
| Malformed policy | Return a `deny` verdict |
| Unknown capability | Return a `deny` verdict |
| Approval lookup failure | Return `deny` or raise an operational error treated as blocked |
| Expired approval | Return a `deny` verdict |
| Adapter exception before tool invocation | Raise an operational error; caller must treat as blocked |
| Audit write failure | Return `deny` or raise an explicit operational error for high-risk paths |

## Fail-open vs fail-closed

| Fail-open agent path | CapFence fail-closed path |
|---|---|
| Prompt tells the model not to run unsafe commands. | Runtime policy evaluates the command before execution. |
| Unknown cases may still reach the tool. | Unknown capabilities deny by default. |
| Errors can disappear into agent retries. | Errors become blocked decisions or operational errors treated as blocks. |
| Logs explain after the side effect. | The side effect is prevented first. |

## Operator visibility

Fail-closed behavior should produce:

- A blocked response to the agent.
- A decision reason.
- An audit entry when persistence is available.
- A clear operational error when audit persistence is unavailable.

Silent blocks are hard to debug. Silent allows are worse.

## Deployment note

Before using CapFence in a high-risk execution path, test the exact adapter, policy file, approval store, and audit persistence configuration you plan to deploy.
