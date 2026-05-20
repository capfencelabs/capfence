# Operational Pattern 05: Experimental Agent Handoff Checks

Multi-agent systems can pass untrusted context into privileged execution. CapFence can evaluate adapter-provided handoff metadata before allowing a privileged tool call.

## Threat

A recursive workflow escalates from low-risk planning into privileged billing execution.

```text
billing.adjust_credit actor=worker-agent source=unverified_planner
```

## Request

```text
actor: worker-agent
capability: billing.adjust_credit.production
payload: {"customer_id": "cus_123", "amount": 500}
metadata: {"upstream_node": "public-planner", "verified_handoff": false}
```

## Policy

```yaml
deny:
  - capability: billing.adjust_credit.production
    verified_handoff: false

require_approval:
  - capability: billing.adjust_credit.production

allow:
  - capability: billing.read
```

## Decision

```text
decision: DENY
reason: unverified_agent_handoff
tool_invoked: false
```

The privileged billing tool does not run for unverified handoff paths.

## Replay

```bash
capfence replay handoff.jsonl --policy policies/handoffs.yaml
```

Use replay to compare policy changes against historical multi-agent handoff metadata.

## Audit

Record actor chain, handoff metadata, capability, policy hash, decision, and replay identifier.

## What CapFence does not solve

This is an experimental pattern. CapFence does not provide a complete distributed identity or provenance system for multi-agent runtimes.
