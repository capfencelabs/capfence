# External Policy Backends

CapFence keeps the local YAML backend as the default policy engine. Advanced users can integrate centralized policy systems through `capfence.core.policy_backends`.

## Backend contract

Input:

- Normalized capability string.
- Context such as actor, environment, tenant, risk level, and tool name.
- Payload with the final tool arguments.

Output:

- `verdict`: `allow`, `deny`, or `require_approval`.
- `reason`: operator-readable reason.
- `matched_policy`: optional metadata for audit and explain output.

## OPA path

`OPAPolicyBackend` posts to an OPA HTTP decision endpoint with this input shape:

```json
{
  "input": {
    "capability": "shell.exec",
    "context": {"environment": "production"},
    "payload": {"command": "sudo systemctl restart nginx"}
  }
}
```

Expected response:

```json
{
  "result": {
    "verdict": "require_approval",
    "reason": "production shell privilege escalation"
  }
}
```

OPA timeouts, connection failures, invalid JSON, and invalid decision shapes fail closed as `deny`.

## Cedar status

Cedar support is deferred pending a data-model fit check. CapFence events map naturally to actions and context, but resource modeling varies by tool boundary and requires a clearer entity model before first-class support.
