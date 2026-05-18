# Require Human Approval

Some actions are too consequential to allow or deny automatically. CapFence's approval workflow pauses agent execution and routes the request to a human reviewer.

## How approval works

1. The agent calls a tool.
2. The gate evaluates the call and matches a `require_approval` rule.
3. The call is stored in the approval queue with full context.
4. The agent is notified the action is pending.
5. A human approves or rejects via CLI or API.
6. If approved, the tool executes. If rejected or expired, it does not.

## Policy configuration

```yaml
require_approval:
  - capability: payments.transfer
    amount_gt: 1000
  - capability: database.write
    environment: production
  - capability: filesystem.delete
  - capability: shell.execute
    contains: "systemctl"
```

## Inline override

When using the direct runtime API, you can require approval for a call regardless of policy by setting the metadata field:

```python
event = ActionEvent.create(
    actor="finance-agent",
    action="transfer",
    resource="payments",
    payload={"amount": 5000},
    metadata={"require_approval": True}
)
verdict = runtime.execute(event)
```

## Viewing pending approvals

```bash
capfence pending-approvals
```

```
ID          Capability            Agent            Requested          Amount
a1b2c3d4    payments.transfer     finance-agent    2024-01-15 10:23   $2,500.00
e5f6g7h8    database.write        db-agent         2024-01-15 10:31   —
```

## Approving and rejecting

```bash
capfence approve a1b2c3d4
capfence reject e5f6g7h8
```

## Python API

```python
from capfence import ApprovalEngine

engine = ApprovalEngine(db_path="capfence_approvals.db")

# List pending approvals
pending = engine.get_pending_approvals()
for req in pending:
    print(req["id"], req["capability"], req["agent_id"])

# Approve
engine.approve_request("a1b2c3d4", resolved_by="alice@company.com")

# Reject
engine.reject_request("e5f6g7h8", resolved_by="bob@company.com")
```

## Approval expiration

Pending approvals expire after a configurable timeout. Expired approvals are automatically rejected:

```yaml
# policies/my_policy.yaml
approval_timeout_seconds: 3600  # 1 hour
```

After expiration, the agent's pending call fails with `approval_expired`.

## Audit trail

All approval actions are recorded:

```bash
capfence logs --audit-log audit.db --json
```

The log includes who approved or rejected, when, and the original request context. This is tamper-evident via the hash chain.

## Related guides

- [Protect payment agents](protect-payment-agents.md)
- [Approval workflows example](../examples/approval-workflows.md)
