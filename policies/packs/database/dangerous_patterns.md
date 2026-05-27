# Database Dangerous Patterns

Review SQL requests that include:

- Schema mutation: `DROP`, `TRUNCATE`, or `ALTER`.
- Broad reads such as `SELECT *`.
- Writes in production: `UPDATE`, `DELETE`, or `INSERT`.
- Missing tenant, user, or environment predicates.
- Missing `LIMIT` on agent-generated reads.
