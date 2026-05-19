# Observe Mode Rollout

Deploying CapFence in strict block mode immediately can surface policy gaps that block legitimate agent behavior. To keep enforcement boring, calm, and predictable, CapFence enforces a strict fail-closed architecture at the code level, but allows you to run a safe rollout period by configuring declarative `warn` rules in your policy.

Declarative warning rules log decisions to the audit database without blocking tool execution. You tune your policy on real traffic, then flip to strict enforcement.

---

## The Rollout Pattern

1. **Observe**: Map capabilities in your policy to the `warn` action. This logs all tool calls without blocking.
2. **Tune**: Adjust policy rules based on what you see in the audit log.
3. **Enforce**: Transition rule actions from `warn` to `deny` or `require_approval` with confidence.

---

## Step 1: Write an Observe Policy

Instead of blocking tool use, define a policy that uses the `warn` action for suspicious or unverified capabilities:

```yaml
# policies/shell_rollout.yaml

deny:
  - capability: shell.execute
    contains: "rm -rf" # Block catastrophic commands immediately

require_approval: []

warn:
  - capability: shell.execute # Log all execution context without blocking
  - capability: filesystem.write

allow:
  - capability: filesystem.read
```

## Step 2: Initialize ActionRuntime

Pass the rollout policy to the adapters or use it directly via `ActionRuntime`:

```python
from capfence import CapFenceTool, ActionRuntime

runtime = ActionRuntime.from_policy("policies/shell_rollout.yaml")

safe_tool = CapFenceTool(
    tool=my_tool,
    agent_id="prod-agent",
    capability="shell.execute",
    gate=runtime
)
```

During this rollout:
- Every tool call is evaluated against your policy.
- Warning events match the `warn` block, which logs a full verdict record to your audit database (`audit.db`).
- The agent continues to run without interruptions because `warn` verdicts are authorized.

---

## Step 3: Review Observed Logs

Query the local audit database using the CLI to see what would have been blocked:

```bash
capfence logs --audit-log audit.db
```

Identify patterns:
- Are any warned actions legitimate calls your agent needs? Move them to the `allow` block.
- Are there dangerous commands that should be strictly blocked? Prepare `deny` rules for them.
- Are there transaction thresholds that require human sign-off? Plan your `require_approval` thresholds.

---

## Step 4: Simulate Policy Changes

Before pushing policy updates to production, export your traffic and dry-run it against your new strict policy:

```bash
capfence replay audit.jsonl --policy policies/shell_production.yaml
```

This validates how your updated strict policy would have handled all real traffic from the observe period — before you deploy it.

---

## Step 5: Switch to Enforce Mode

Once you are confident in your rule coverage, switch the actions in your policy file to `deny` or `require_approval`:

```yaml
# policies/shell_production.yaml

deny:
  - capability: shell.execute
    contains: "rm -rf"
  - capability: shell.execute
    contains: "curl"

require_approval:
  - capability: shell.execute
    contains: "systemctl"

allow:
  - capability: shell.execute
  - capability: filesystem.read
```

Since the policy is loaded at startup, updating the yaml file updates enforcement parameters safely and immediately.

---

## Related Guides

- [Protect shell tools](protect-shell-tools.md)
- [Require human approval](require-human-approval.md)
