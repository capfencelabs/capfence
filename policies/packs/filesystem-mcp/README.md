# Filesystem and MCP Policy Pack

Use this pack for `file.read`, `file.write`, `file.delete`, and `mcp.tools.call`.

Normalize paths to absolute canonical paths before evaluation, resolve symlinks, and reject relative traversal before forwarding the request. For MCP, normalize the JSON-RPC `tools/call` method into a stable capability and include the tool name in context.

Limitations: CapFence can only authorize the payload it receives. It does not prove that a malicious tool implementation respects the normalized path or declared MCP tool name.
