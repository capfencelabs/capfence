# Operational Pattern 02: Shell Execution Boundary

Shell access is one of the highest-risk capabilities an agent can hold. CapFence wraps the shell tool and evaluates command shape before a process is spawned.

## Threat

An autonomous ops agent attempts destructive production execution.

```text
shell.exec rm -rf /var/lib/postgresql
```

## Request

```text
actor: ops-agent
capability: shell.exec.production
payload: {"command": "rm -rf /var/lib/postgresql", "cwd": "/"}
environment: production
```

## Policy

```yaml
deny:
  - capability: shell.exec.production
    contains: "rm -rf"
  - capability: shell.exec.production
    contains: "curl"

allow:
  - capability: shell.exec.readonly
```

## Decision

```text
decision: DENY
reason: destructive_command_pattern
tool_invoked: false
```

The host shell never receives the denied command.

## Replay

```bash
capfence replay shell-audit.jsonl --policy policies/shell.yaml
```

Use replay to test new deny rules against recent shell requests before putting them in production.

## Audit

Record the actor, command, working directory, environment, matched rule, decision, and replay identifier.

## What CapFence does not solve

CapFence does not replace process sandboxing, container isolation, OS permissions, or network egress control. It controls the gated shell tool path before process spawn.
