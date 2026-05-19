# MCP Integration

CapFence provides a transparent stdio-proxying gateway for any MCP server. It evaluates every `tools/call` request against your policy before forwarding it to the upstream server.

## How it works

The gateway intercepts JSON-RPC messages on stdin, extracts `params.arguments` from `tools/call` requests, evaluates them against the gate, and either forwards the message or returns a standardized `−32000` error to the client. The upstream MCP server never receives blocked calls.

## Setup

```python
from capfence.mcp.gateway import MCPGatewayServer

gateway = MCPGatewayServer(
    upstream_command=["python", "-m", "mcp_server_filesystem", "/data"],
    policy_path="policies/mcp.yaml",
    agent_id="mcp-agent"
)

gateway.run()
```

## Client configuration

Run the gateway as the process your MCP client connects to. If you need a CLI wrapper for a specific desktop client, create a small Python entrypoint that constructs `MCPGatewayServer` with your upstream command and policy path.

```python
from capfence.mcp.gateway import MCPGatewayServer

MCPGatewayServer(
    upstream_command=["python", "-m", "mcp_server_filesystem", "/data"],
    policy_path="policies/mcp.yaml",
    agent_id="desktop-agent",
).run()
```

## Policy for MCP

```yaml
# policies/mcp.yaml

deny:
  - capability: mcp.tool.execute
    tool_name: "delete_*"
  - capability: mcp.tool.execute
    tool_name: "shell_*"

require_approval:
  - capability: mcp.tool.execute
    tool_name: "write_*"
    path_prefix: "/data/prod"

allow:
  - capability: mcp.tool.execute
```

## Blocked call response

When a call is blocked, the client receives a JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "CapFence blocked this tool call"
  }
}
```

## Audit trail

All MCP tool calls are logged with the full JSON-RPC payload hash:

```bash
capfence logs --agent mcp-agent
```

## Related guides

- [Secure MCP servers](../guides/secure-mcp-servers.md)
- [MCP governance example](../examples/mcp-governance.md)
