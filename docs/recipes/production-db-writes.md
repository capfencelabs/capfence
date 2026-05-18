# Protect Production DB Writes

## Policy

```yaml
deny:
  - capability: database.drop

require_approval:
  - capability: database.write
    environment: production

allow:
  - capability: database.read
  - capability: database.write
    environment: staging
```

## Integration

```python
from capfence import ActionRuntime, ActionEvent

# 1. Initialize ActionRuntime canonical engine
runtime = ActionRuntime.from_policy("policies/db.yaml")

# 2. Formulate the governed event
event = ActionEvent.create(
    actor="db-agent",
    action="write",
    resource="database",
    environment="production",
    payload={"query": "update accounts set status='inactive'"}
)

# 3. Deterministic execution authorization check
verdict = runtime.execute(event)
```

## Expected result

- Production writes require approval.
- Staging writes pass.
