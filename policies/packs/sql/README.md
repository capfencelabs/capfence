# SQL Policy Pack

Use this pack for `db.query`, `sql.execute`, and `warehouse.query` boundaries.

Include structured metadata when possible: schema, table, query type, row estimate, tenant, and PII classification. These examples use string and regex matching and are not semantic SQL authorization. Production adapters should parse SQL or rely on database-native authorization in addition to CapFence.
