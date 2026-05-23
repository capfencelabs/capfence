# Compatibility Matrix

This page describes adapter compatibility and assumptions. Adapters are intentionally lightweight and depend on the target framework's public tool interface. If your version diverges, use the custom framework pattern.

| Framework | Adapter | Maturity | Compatibility | Notes |
| --- | --- | --- | --- | --- |
| LangChain | `capfence.framework.langchain.CapFenceTool` | Beta | Latest stable 0.1+ | Wraps `BaseTool` or duck-typed tools with `run`/`arun`. |
| LangGraph | `capfence.framework.langgraph.CapFenceToolNode` | Beta | Latest stable 0.1+ | Wraps tool nodes; expects standard tool node inputs. |
| CrewAI | `capfence.framework.crewai.CapFenceCrewAITool` | Beta | Latest stable 0.30+ | Wraps tools with `run`/`arun`. |
| OpenAI Agents SDK | `capfence.framework.openai_agents.CapFenceOpenAITool` | Beta | Latest stable | Uses `on_invoke_tool` callback with JSON args. |
| MCP | `capfence.mcp.gateway.MCPGatewayServer` | Experimental | MCP spec 2024+ | Intercepts `tools/call` requests on stdio. |
| PydanticAI | `capfence.framework.pydanticai.CapFencePydanticTool` | Experimental | Latest stable | Wraps callables used as tools. |
| LlamaIndex | `capfence.framework.llamaindex.CapFenceLlamaIndexTool` | Experimental | Latest stable | Wraps tools exposing `call`/`acall` or `__call__`. |
| AutoGen | `capfence.framework.autogen.CapFenceAutoGenTool` | Experimental | Latest stable | Wraps tool callables used in agent tool registries. |

## Notes

- Use `Custom frameworks` if your framework version uses a different tool interface.
- All adapters are duck-typed to avoid heavy dependencies.
- Report incompatibilities with the tool signature and a minimal repro snippet.
