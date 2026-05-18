# CapFence Case Studies

Welcome to the CapFence Case Studies directory. These documents provide extensive, production-grade blueprints illustrating how to enforce deterministic execution boundaries and cryptographic audit trails across five high-risk operational domains.

Each case study includes an executive threat analysis, a declarative YAML capability policy, a complete annotated Python implementation, and an operational security analysis.

---

## 📂 Case Study Index

### [1. Fintech & Automated Payments Gating](01_fintech_payments.md)
* **Domain**: Financial Systems & Automated Transfers
* **Threat**: Model hallucinations and prompt injections exfiltrating corporate funds.
* **Solution**: Declarative amount-based threshold gating, automatic risk priority mapping, and database-backed human approval queue escalation.

### [2. Secure Shell & DevOps Execution](02_secure_shell_devops.md)
* **Domain**: Cloud Infrastructure & System Operations
* **Threat**: AI agents executing destructive terminal commands (`rm -rf`, raw socket curls) due to compromise or query drift.
* **Solution**: Regular expression CLI payload interceptors, system-level capability blocklists, and immediate fail-closed execution rejection.

### [3. Model Context Protocol (MCP) Boundary Security](03_mcp_boundary_security.md)
* **Domain**: Local Desktop Agent Tooling (Claude Desktop, Cursor)
* **Threat**: Malicious codebases exfiltrating SSH keys or modifying host filesystems via MCP tools.
* **Solution**: Transparent stdio JSON-RPC proxy gateway mapping, workspace directory sandboxing, and standardized error injection.

### [4. Database Write & DDL Guardrails](04_database_ddl_guardrails.md)
* **Domain**: Data Persistence & Warehousing
* **Threat**: Non-deterministic SQL generators executing unstructured DDL drops or unindexed bulk deletes.
* **Solution**: Pre-execution SQL AST keyword scanning, schema change blocklists, and administrator approval workflows.

### [5. Multi-Agent Collaboration & Trust Lineage](05_multi_agent_trust_lineage.md)
* **Domain**: Autonomous Multi-Agent Networks (LangGraph / CrewAI)
* **Threat**: Prompt injection propagating from public-facing agents to highly privileged backend tool agents.
* **Solution**: In-transit execution tracing (`FlowTracer`), cross-boundary state validation, and identity-bound lineage authorization.

---

## 🛠️ Getting Started Locally
You can run any of the case studies directly. Every application leverages CapFence's local-first architecture:
* **Zero Network Latency**: Real-time policy evaluation in `<1ms`.
* **Zero Cloud Dependencies**: Runs entirely offline in local Python runtimes.
* **Cryptographic Trust**: Logs all decisions into a local, tamper-evident SHA-256 database.
