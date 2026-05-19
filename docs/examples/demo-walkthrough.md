# Demo Walkthrough

This demo highlights CapFence's static scan, live gate decisions, trace replay, and audit verification workflows using the bundled fintech demo project.

## Why this demo exists

Prompt guardrails are not enforcement. This demo shows a deterministic gate that blocks tool calls before execution and records a tamper-evident audit trail.

## Where it sits in your stack

```
Agent framework -> CapFence gate -> Tool/API/DB/Shell
```

CapFence does not replace sandboxing or least-privilege credentials. It complements them by enforcing runtime policy at the tool boundary.

## Rollout story (observe → enforce → audit)

1. Observe: scan the codebase and export machine-readable coverage.
2. Enforce: block and allow real tool calls with policy.
3. Audit: verify the hash chain and replay traces.

## Prerequisites

- Python 3.10+
- Local repo checkout
- Virtual environment with CapFence installed (`pip install -e ".[dev]"`)

## Run the demo

```bash
chmod +x ./scripts/demo.sh
./scripts/demo.sh
```

## Optional: add a short overlay for the cast

If you share the demo cast, add a brief text overlay (or preface) that says:

"This is a deterministic gate between an agent and its tools. The demo shows scan, enforcement, simulation, and audit verification in under two minutes."

## Expected output (example)

```text
[DEMO] Running CapFence demo from repo root
[DEMO] Deterministic runtime authorization for agent tool calls, enforced before execution.
[SCAN] 8 tool(s) found in capfence-demo/src
  Gated: 8
  Ungated: 0

[SCAN] JSON report written to /tmp/capfence-demo-scan.json
[RUNTIME] blocked authorized=False decision=deny reason=policy_deny
[RUNTIME] allowed authorized=True decision=allow reason=policy_allow
Replayed 1 events:
  Authorized:         1
  Blocked:            0
  Requires Approval:  0
  Drifts/Diffs:       0
[VERIFY] Audit chain: VALID
  No tampering detected.
[POLICY] VALID: policies/production_shell_policy.yaml
  Rules: 2
  Risk levels: 0
```

## Next steps

- Try `capfence check` on your own project.
