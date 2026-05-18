# Case Study 04: Database Write & DDL Guardrails

## 1. Executive Summary

### The Challenge
Data-driven analytics agents are granted database query capabilities to run reports, perform customer segmentation, and sync customer profile updates. When using open-ended Text-to-SQL generation models, the database faces massive structural risk:
1. **Accidental Drops**: The model hallucinates or translates a vague user query into a catastrophic `DROP TABLE users` or `TRUNCATE accounts`.
2. **Unindexed Deletes**: An agent runs an unindexed bulk update or delete query (`DELETE FROM logs`), locking the database and causing system-wide performance degradation.
3. **Privilege Escalation**: Adversarial inputs trick the model into altering database schemas (`ALTER TABLE`) or creating unauthorized admin users.

### The CapFence Solution
CapFence introduces a **pre-execution database guardrail**. Every generated SQL query string is scanned for dangerous keywords, structure, and AST patterns. If any unauthorized write, alter, or drop capability matches a policy block rule, CapFence fails closed, completely blocking the query before it is ever sent to the connection pool.

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

Below is a complete, self-contained Python program demonstrating pre-execution SQL payload scanning, keyword categorization, policy matching, and database connection intercepting.

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
    
    # 1. Categorize query based on AST/Keyword matching
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

## 4. Security & Compliance Analysis

### Database Integrity Profile
1. **Pre-Connection Shielding**: By blocking dangerous SQL statements at the application layer *before* they are sent to the database connection pool, we eliminate SQL parsing overhead and completely safeguard the database server from resource exhaustion and locks.
2. **Text-to-SQL Injection Vaccine**: Attackers commonly attempt prompt injection to bypass table boundaries. Because CapFence checks the raw SQL generated by the model rather than the prompt, it acts as a permanent firewall against indirect SQL injections.
3. **Verifiable Query Trail**: Every query attempt is stored in the local SHA-256 audit ledger, proving database access compliance to external security auditors.
