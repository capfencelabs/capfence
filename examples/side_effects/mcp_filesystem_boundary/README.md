# MCP Filesystem Boundary

This demo shows CapFence denying an MCP filesystem request before the upstream server receives it.

## Scenario

An IDE agent asks an MCP filesystem server to read outside the workspace:

```txt
~/.ssh/id_rsa
```

CapFence denies before proxying to the upstream MCP server.

## Run

```bash
python3 capfence_proxy_demo.py
```
