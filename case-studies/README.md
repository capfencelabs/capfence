# CapFence Case Studies

Welcome to the CapFence Case Studies directory. These blueprints illustrate how to enforce deterministic execution boundaries and cryptographic audit trails across five high-risk operational domains.

Each case study includes an executive threat analysis, a declarative YAML capability policy, a complete annotated Python implementation, and an operational security analysis.

---

## 📂 Example Scenarios

### [1. Preventing unauthorized fund transfers](01_fintech_payments.md)
A trading or treasury agent attempts to transfer corporate funds beyond its approved daily threshold.

CapFence intercepts the action before execution, requiring an expiring human-in-the-loop pre-authorization.

### [2. Blocking destructive shell execution](02_secure_shell_devops.md)
An autonomous ops agent attempts to run a dangerous terminal command:
```bash
rm -rf /var/lib/postgresql
```
CapFence intercepts the raw CLI command string before execution and blocks it using local deterministic deny policies.

### [3. Sandboxing desktop agent MCP tools](03_mcp_boundary_security.md)
A local IDE agent hijacked by repository-level prompt injection attempts to read files outside the project directory.

CapFence gateway proxies the stdio JSON-RPC stream, blocking host traversals and returning standard protocol errors.

### [4. Guarding database write and schema modifications](04_database_ddl_guardrails.md)
An SQL-generating analytics agent attempts to drop tables or run unindexed bulk deletes.

CapFence parses the generated queries pre-execution, blocking DDL/DML operations before they hit the connection pool.

### [5. Enforcing multi-agent trust and lineage](05_multi_agent_trust_lineage.md)
A compromised public-facing routing agent propagates a prompt-injected payload to a privileged billing agent.

CapFence tracks the full node execution lineage, blocking execution if the transaction has been touched by an unverified node.

---

## 🛠️ Getting Started Locally
You can run any of these case studies directly. Every application leverages CapFence's local-first architecture:
* **Zero Network Latency**: Real-time policy evaluation in `<1ms`.
* **Zero Cloud Dependencies**: Runs entirely offline in local Python runtimes.
* **Cryptographic Trust**: Logs all decisions into a local, tamper-evident SHA-256 database.
