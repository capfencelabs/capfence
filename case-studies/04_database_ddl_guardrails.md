# Operational Pattern 04: Database Write & Schema-Change Boundary

Text-to-SQL agents can generate destructive queries. CapFence evaluates the request class before the database connection executes it.

## Threat

An analytics agent generates destructive production SQL.

```text
database.query DELETE FROM customers
```

## Request

```text
actor: analytics-agent
capability: database.query.production
payload: {"sql": "DELETE FROM customers"}
environment: production
```

## Policy

```yaml
deny:
  - capability: database.query.production
    contains: "DROP TABLE"
  - capability: database.query.production
    contains: "DELETE FROM"

require_approval:
  - capability: database.write.production

allow:
  - capability: database.read.production
```

## Decision

```text
decision: DENY
reason: destructive_sql_pattern
query_executed: false
```

The database connection does not receive the denied query.

## Replay

```bash
capfence replay db-audit.jsonl --policy policies/database.yaml
```

Use replay to test whether candidate SQL rules would block prior generated queries.

## Audit

Record actor, query class, payload hash, environment, matched rule, decision, and replay identifier.

## What CapFence does not solve

CapFence is not a full SQL firewall or query optimizer. Keep database-native permissions, transaction controls, backups, and query review in place.
