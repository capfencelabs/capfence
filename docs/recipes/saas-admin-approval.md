# Require Approval For SaaS Admin Changes

## Policy

```yaml
require_approval:
  - capability: saas.user.role_change
  - capability: saas.org.permission_change

deny:
  - capability: saas.user.disable_mfa

allow:
  - capability: saas.user.read
  - capability: saas.org.read
```

## Integration

```python
from capfence import ActionRuntime, ActionEvent

# 1. Initialize ActionRuntime canonical engine
runtime = ActionRuntime.from_policy("policies/saas.yaml")

# 2. Formulate the governed event
event = ActionEvent.create(
    actor="admin-agent",
    action="role_change",
    resource="saas.user",
    environment="production",
    payload={"user_id": "u_123", "role": "owner"}
)

# 3. Deterministic execution authorization check
verdict = runtime.execute(event)
```

## Expected result

- Role or permission changes require approval.
- MFA disablement is blocked.
