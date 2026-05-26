# Production Shell Boundary

This demo shows CapFence blocking a dangerous AI agent shell command before the process is spawned.

## Scenario

An ops agent proposes:

```bash
rm -rf /var/lib/postgresql
```

Without an execution boundary, this could run.

With CapFence:

```txt
decision: DENY
reason: destructive production filesystem operation
tool_invoked: false
```

## Run

```bash
python3 run_demo.py
```

## Expected Output

```txt
CapFence production shell boundary demo

Agent requested:
  tool: shell.exec
  environment: production
  command: rm -rf /var/lib/postgresql

CapFence decision:
  decision: DENY
  reason: destructive_or_secret_exfiltration_risk
  tool_invoked: false

Audit:
  written: audit_sample.jsonl
  replay: capfence replay audit_sample.jsonl --policy policy.yaml
```
