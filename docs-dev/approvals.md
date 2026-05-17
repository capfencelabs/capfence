# Human Approval Workflows and Pre-Authorizations

CapFence supports approval-based runtime governance, allowing you to define policies that require validation before high-risk operations execute.

---

## 1. Interactive Approval Requests (Human-in-the-Loop)

When an agent triggers a capability that requires manual approval (e.g. `require_approval` in policy), CapFence raises a pending request. The action is held (fail-closed) until an operator resolves it.

### Programmatic API

```python
from capfence import ApprovalEngine

manager = ApprovalEngine("approvals.db")

# Create a pending approval request
req = manager.request_approval(
    agent_id="my-agent",
    tool_name="transfer_funds",
    capability="payment.execute.high_value",
    payload={"amount": 5000, "to": "acme_inc"},
    reason="Transfer exceeds automatic limit",
)

print(f"Approval request {req.id} queued. Status: {req.status}")
```

### CLI Management

Operators can review, approve, or reject pending queue entries directly from the command line:

```bash
# List all pending requests
capfence pending-approvals

# Approve a request
capfence approve <request_id> --by ops_manager

# Reject a request
capfence reject <request_id> --by ops_manager
```

---

## 2. Pre-Authorized Capability Grants

Operations administrators, CI/CD pipelines, or Slack bots can provision temporary, time-bound, or session-bound capability credentials directly to an actor. When the agent attempts the action, the [ApprovalEngine](file:///capfence/core/approvals.py#L44) evaluates the active grants and authorizes the call automatically.

### CLI Grants

```bash
# Grant a 10-minute temporary capability for hotfix deployment
capfence grant --actor hotfix-agent --capability deployment.execute.production --duration 600

# Grant a session-locked push permission for a specific task run
capfence grant --actor compiler-agent --capability github.push.main --session session-uuid-8899 --by github_actions
```

### Programmatic Validation

```python
from capfence import ApprovalEngine

manager = ApprovalEngine("approvals.db")

# Pre-authorize a temporary capability rule programmatically
manager.grant_temporary_approval(
    actor="ops-agent",
    capability="filesystem.delete.workspace",
    environment="production",
    duration_seconds=300.0,  # 5 minutes
    granted_by="ops_admin"
)

# Validate if an active grant exists
authorized, grant = manager.check_approval(
    actor="ops-agent",
    capability_str="filesystem.delete.workspace",
    environment="production",
)

if authorized and grant:
    print(f"Automatically pre-authorized by grant {grant.id} issued by {grant.granted_by}")
```
