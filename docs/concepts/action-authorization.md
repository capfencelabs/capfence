# Action Authorization

CapFence evaluates proposed actions, not model text.

An action contains:

- actor
- tool or capability
- action
- resource
- payload
- environment
- policy version
- request id
- idempotency key, when applicable

A decision is one of:

- allow
- deny
- require_approval

Denied actions must not reach the downstream tool.

## Example

```json
{
  "actor": "ops-agent",
  "tool": "shell.exec",
  "action": "execute",
  "resource": "host:prod-db-01",
  "environment": "production",
  "payload": {
    "command": "rm -rf /var/lib/postgresql"
  }
}
```

Decision:

```json
{
  "decision": "deny",
  "reason": "destructive command outside approved recovery policy",
  "tool_invoked": false
}
```

## Authorization Boundary

The authorization boundary is the point where model output becomes a tool invocation.

```txt
Agent -> Proposed action -> CapFence -> Gated executor -> Tool
```

CapFence is effective when every side-effectful execution path flows through that boundary.
