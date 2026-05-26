# Database Write Boundary

This demo shows CapFence blocking a destructive text-to-SQL query before it reaches a database executor.

## Scenario

A text-to-SQL workflow proposes:

```sql
DROP TABLE customers;
```

CapFence denies before the query reaches the database connection.

## Run

```bash
python3 run_demo.py
```
