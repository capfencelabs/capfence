# Secure MCP Servers

The Model Context Protocol (MCP) lets agents connect to data sources and tools via a standardized interface. By default, MCP servers execute any tool call they receive. CapFence's MCP gateway sits between the agent and the MCP server, enforcing policy before any call reaches the server.

## The authorization gap

Without CapFence, an MCP server trusts its client completely:

```
Agent → MCP Client → MCP Server → Filesystem / Database
```

If the agent is compromised — via prompt injection, hallucination, or a rogue instruction — the MCP server will execute whatever it is told.

## The CapFence MCP gateway

```
Agent → MCP Client → CapFence Gateway → MCP Server → Filesystem / Database
                              │
                         Policy check
                         Audit log
```

The gateway is a transparent stdio proxy. It intercepts JSON-RPC messages, extracts the tool call arguments, evaluates them against policy, and either forwards the message or returns a standardized error.

## Setup

```python
from capfence.mcp.gateway import MCPGatewayServer
from capfence import ActionRuntime

gateway = MCPGatewayServer(
    upstream_command=["python", "-m", "mcp_server_filesystem", "/data"],
    gate=ActionRuntime.from_policy("policies/mcp_policy.yaml"),
    agent_id="mcp-agent"
)

gateway.run()
```

## MCP policy example

```yaml
# policies/mcp_policy.yaml

deny:
  - capability: filesystem.delete
  - capability: filesystem.write
    path_prefix: "/etc"
  - capability: shell.execute

require_approval:
  - capability: filesystem.write
    path_prefix: "/data/prod"

allow:
  - capability: filesystem.read
  - capability: filesystem.write
    path_prefix: "/data/staging"
```

## What the gateway blocks

When a blocked call is intercepted, the gateway returns a JSON-RPC error to the client:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "AgentActionBlocked: capability=filesystem.delete decision=denied reason=destructive_operation"
  }
}
```

The MCP server never receives the call.

## Audit trail

Every MCP tool call — allowed and blocked — is recorded in the audit log with the full JSON-RPC payload hash:

```bash
capfence logs --agent mcp-agent
```

## Related guides

- [Protect shell tools](protect-shell-tools.md)
- [MCP integration reference](../integrations/mcp.md)
