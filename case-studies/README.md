# CapFence Operational Patterns

These reference patterns illustrate ways to place CapFence at an execution boundary. They are conceptual implementations for local testing and design review, not claims of customer production deployments.

Each pattern includes:

- an operational risk
- a capability policy
- a small Python implementation
- notes on where CapFence sits in the flow

## Patterns

### [1. Payment threshold authorization](01_fintech_payments.md)

A treasury-style agent requests payment execution. CapFence evaluates amount and capability before the payment API would be called.

### [2. Shell execution boundary](02_secure_shell_devops.md)

An ops agent requests shell execution. CapFence evaluates command text and context before a process is spawned.

### [3. MCP filesystem boundary](03_mcp_boundary_security.md)

An MCP client requests filesystem access. CapFence proxies the tool call and evaluates path scope before forwarding to the upstream server.

### [4. Database write and schema-change boundary](04_database_ddl_guardrails.md)

A text-to-SQL style workflow generates database actions. CapFence maps the request to coarse capabilities such as read, write, or schema change before the query is sent.

### [5. Experimental agent handoff checks](05_multi_agent_trust_lineage.md)

A multi-agent workflow passes context between nodes. CapFence evaluates adapter-provided metadata before allowing a privileged action.

## Local use

Run these examples as starting points for your own boundary design. Validate the adapter, policy, audit storage, and failure behavior before using any pattern in a high-risk environment.
