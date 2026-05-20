# Operational Pattern 04: Database Write & Schema-Change Boundary

## 1. Executive Summary

### The Challenge
Data-driven agents may be granted database query capabilities to run reports, perform segmentation, or prepare updates. When using open-ended Text-to-SQL generation, the database faces structural risk:
1. **Accidental Drops**: The model hallucinates or translates a vague user query into a catastrophic `DROP TABLE users` or `TRUNCATE accounts`.
2. **Unindexed Deletes**: An agent runs an unindexed bulk update or delete query (`DELETE FROM logs`), locking the database and causing system-wide performance degradation.
3. **Privilege Escalation**: Adversarial inputs trick the model into altering database schemas (`ALTER TABLE`) or creating unauthorized admin users.

### The CapFence Pattern
CapFence can be placed before the database call as a coarse execution authorization layer. In this reference implementation, the adapter classifies the generated SQL into broad capabilities such as `database.read`, `database.write`, or `database.ddl`, then evaluates that capability against policy before the query is sent to the connection pool.

This example is not a complete SQL firewall or full SQL parser. Treat it as an initial boundary pattern that should be paired with database permissions, query parsing, statement timeouts, and least-privilege credentials.

---

## 2. Declarative Policy (`policies/database_policy.yaml`)

```yaml
# policies/database_policy.yaml
policy_name: Corporate SQL Execution Policy
version: 1.0.0

deny:
  # Block Schema Mutations (DDL)
  - capability: database.ddl
    contains: "drop table"
  - capability: database.ddl
    contains: "truncate"
  - capability: database.ddl
    contains: "alter table"
  # Block massive unindexed operations
  - capability: database.write
    contains: "delete from" # Force approvals for all deletes

require_approval:
  # Manual review for table creations or updates on sensitive namespaces
  - capability: database.write
    contains: "insert into"
  - capability: database.write
    environment: production

allow:
  # Safe reporting reads are permitted globally
  - capability: database.read
```

---

## 3. Reference Implementation

Below is a self-contained Python program demonstrating pre-execution SQL keyword categorization, policy matching, and database connection interception.

```python
import os
from capfence import ActionRuntime, ActionEvent

class MockDBConnection:
    """Simulates an active connection to a production PostgreSQL database."""
    def execute_query(self, sql: str) -> str:
        print(f"🗄️ [DB ENGINE] Successfully executed SQL: {sql}")
        return "Command completed successfully. 1 row affected."

def handle_agent_sql_query(sql_query: str, runtime: ActionRuntime, db_conn: MockDBConnection) -> str:
    """Pre-execution interceptor routing SQL queries through CapFence."""
    sql_lower = sql_query.lower()
    
    # 1. Categorize query with simple keyword matching.
    # Replace this with a proper SQL parser before relying on it for high-risk paths.
    if any(keyword in sql_lower for keyword in ["drop", "truncate", "alter", "create"]):
        resource, action = "database", "ddl"
    elif any(keyword in sql_lower for keyword in ["insert", "update", "delete"]):
        resource, action = "database", "write"
    else:
        resource, action = "database", "read"
        
    # 2. Build our governed action event
    event = ActionEvent.create(
        actor="analytics-agent",
        action=action,
        resource=resource,
        environment="production",
        risk="high" if action == "write" else "low",
        payload={"query": sql_query}
    )
    
    # 3. Evaluate the query against CapFence policies
    verdict = runtime.execute(event)
    
    if verdict.authorized:
        print(f"✅ [DATABASE GATING] Query authorized. Dispatching to connection pool...")
        return db_conn.execute_query(sql_query)
    else:
        raise PermissionError(
            f"❌ [SECURITY BLOCK] Denied dangerous SQL execution: capability={resource}.{action} reason={verdict.reason}"
        )

def run_database_guard_demo():
    policy_path = "policies/database_policy.yaml"
    
    # Write our corporate database policy
    os.makedirs("policies", exist_ok=True)
    with open(policy_path, "w") as f:
        f.write("""
deny:
  - capability: database.ddl
    contains: "drop table"
  - capability: database.write
    contains: "delete from"
allow:
  - capability: database.read
  - capability: database.write
""")

    runtime = ActionRuntime.from_policy(policy_path)
    db_conn = MockDBConnection()
    print("🚀 Database Pre-Execution Guard initialized successfully.")

    # ----------------------------------------------------
    # Query 1: Safe Analytics Report (SELECT count)
    # ----------------------------------------------------
    print("\n--- Scenario 1: Allowed Diagnostic SQL ---")
    sql_safe = "SELECT count(*) FROM users WHERE status = 'active';"
    try:
        handle_agent_sql_query(sql_safe, runtime, db_conn)
    except PermissionError as e:
        print(e)

    # ----------------------------------------------------
    # Query 2: Catastrophic DDL (DROP TABLE users)
    # ----------------------------------------------------
    print("\n--- Scenario 2: Catastrophic DDL Drop Intercepted ---")
    sql_ddl = "DROP TABLE users;"
    try:
        handle_agent_sql_query(sql_ddl, runtime, db_conn)
    except PermissionError as e:
        print(e)

    # ----------------------------------------------------
    # Query 3: Destructive DML (DELETE FROM logs)
    # ----------------------------------------------------
    print("\n--- Scenario 3: Destructive DML Deletion Blocked ---")
    sql_dml = "DELETE FROM logs;"
    try:
        handle_agent_sql_query(sql_dml, runtime, db_conn)
    except PermissionError as e:
        print(e)

if __name__ == "__main__":
    run_database_guard_demo()
```

---

## 4. Operational Notes

1. **Pre-execution boundary**: The adapter checks a coarse database capability before dispatching to the connection pool.
2. **Prompt-independent decision**: Policy evaluates the generated request, not a model's claim that the request is safe.
3. **Audit trail**: Decisions can be written to the local audit log for replay and review.
4. **Limit**: Keyword matching is not enough for mature SQL enforcement. Use database-native permissions and a real SQL parser for serious deployments.
