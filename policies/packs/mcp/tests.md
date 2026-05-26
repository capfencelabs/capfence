# MCP Policy Pack Tests

Minimum checks before adapting this pack:

- `mcp.filesystem.read` for `~/.ssh/id_rsa` is denied.
- `mcp.filesystem.read` for `/etc/passwd` is denied.
- `mcp.filesystem.write` for `../../app.py` is denied.
- `mcp.filesystem.read` for `./workspace/report.md` is allowed.
- `mcp.shell.exec` for `rm -rf /tmp/workspace` is denied.
