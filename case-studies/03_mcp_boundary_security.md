# Operational Pattern 03: MCP Filesystem Boundary

MCP servers often trust the client completely. CapFence runs as a proxy before the upstream MCP server and evaluates each tool call.

## Threat

A compromised IDE agent asks an MCP filesystem server to read secrets outside the workspace.

```text
mcp.filesystem.read path=../../.env
```

## Request

```text
actor: ide-agent
capability: mcp.filesystem.read
payload: {"tool": "read_file", "path": "../../.env"}
environment: developer_workstation
```

## Policy

```yaml
deny:
  - capability: mcp.filesystem.read
    path_contains: "../"
  - capability: mcp.filesystem.read
    path_contains: ".env"

allow:
  - capability: mcp.filesystem.read
    path_prefix: "/workspace/project"
```

## Decision

```text
decision: DENY
reason: path_traversal_or_secret_read
upstream_mcp_invoked: false
```

The upstream MCP server never receives the blocked JSON-RPC request.

## Replay

```bash
capfence replay mcp.jsonl --policy policies/mcp.yaml
```

Use replay to test workspace allowlist changes against real MCP traffic.

## Audit

Record the JSON-RPC payload hash, tool name, path, actor, policy hash, decision, and replay identifier.

## What CapFence does not solve

CapFence does not make an unsafe MCP server safe if agents can bypass the proxy. It controls the MCP path you route through the gateway.
