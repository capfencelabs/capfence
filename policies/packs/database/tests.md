# Database Policy Pack Tests

Minimum checks before adapting this pack:

- `DROP TABLE customers;` is denied.
- `SELECT * FROM customers;` is denied.
- `UPDATE customers SET tier = 'vip';` requires approval in production.
- `SELECT name FROM customers WHERE id = 1 LIMIT 1` is allowed.
