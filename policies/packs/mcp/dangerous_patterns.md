# MCP Dangerous Patterns

Review MCP requests that include:

- Filesystem access outside the workspace.
- Secret paths such as `.env`, `~/.ssh`, or cloud credential files.
- Shell execution through an MCP server.
- Database or SaaS admin actions hidden behind generic MCP tool names.
- Delete operations without explicit approval policy.
