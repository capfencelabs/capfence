# Installation

CapFence requires Python 3.10 or later.

## Install from PyPI

```bash
pip install capfence
```

## Install with optional framework extras

```bash
# LangChain / LangGraph support
pip install "capfence[langchain]"

# CrewAI support
pip install "capfence[crewai]"

```

## Verify the installation

```bash
capfence --version
```

## What gets installed

| Component | Purpose |
|---|---|
| `capfence` CLI | Scan, audit, replay, approve |
| `capfence.ActionRuntime` | Runtime authorization for direct API use |
| `capfence.framework.*` | Framework-specific wrappers |
| `capfence.mcp.gateway` | MCP governance gateway |
| Local SQLite audit database | Created when a runtime or CLI command writes audit events |

## Next steps

- [Quickstart](quickstart.md) — wrap your first tool in under 5 minutes
- [First policy](first-policy.md) — write a policy that blocks and allows
- [First blocked action](first-blocked-action.md) — see enforcement in action
