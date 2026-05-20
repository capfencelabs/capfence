# MCP Interception Model

CapFence can sit in front of an MCP server as an authorization proxy. The proxy receives MCP tool calls, maps them to capability context, evaluates policy, and only forwards allowed requests.

## Flow

```text
MCP client
  -> tools/call JSON-RPC request
  -> CapFence MCP gateway
  -> policy evaluation
  -> upstream MCP server only if allowed
```

## Request mapping

An MCP request becomes an `ActionEvent` using fields such as:

- tool name
- method
- arguments
- workspace path
- actor or client identity when available
- environment or policy context

```yaml
allow:
  - capability: mcp.filesystem.read
    path_prefix: "/workspace/docs"
```

## Boundaries

The gateway can block tool calls before the upstream MCP server receives them. It does not make an unsafe MCP server safe by itself. The upstream server should still run with least privilege, constrained filesystem access, and normal host-level controls.
