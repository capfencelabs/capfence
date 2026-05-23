# Product Positioning

Models may propose actions. CapFence authorizes side effects.

CapFence is the deterministic authorization point between an AI agent and the tools that mutate systems, move money, read sensitive files, run shell commands, or call downstream APIs.

## Maturity label

CapFence is pre-1.0 public beta infrastructure.

This means:

- Policy decisions are deterministic for the normalized event and fail closed by default.
- Public APIs may still change before 1.0.
- The local YAML backend is the default and most mature backend.
- Integrations and policy packs should be validated against your own tool payloads before production use.
- CapFence should be deployed alongside sandboxing, IAM, secrets management, and downstream authorization.

## What CapFence is not

| Category | What it does | CapFence relationship |
| --- | --- | --- |
| Prompt guardrails | Shape model input or output | Complementary; prompts are not authorization boundaries. |
| Content moderation | Classify unsafe text or media | Complementary; CapFence authorizes execution, not content safety. |
| Sandboxing | Constrain process, filesystem, or network behavior | Required defense in depth for untrusted execution. |
| IAM | Grants identities access to systems | CapFence should call tools through least-privilege identities. |
| Execution authorization | Decide whether a tool call may proceed | CapFence's primary role. |

## Integration maturity

| Integration | Maturity | Notes |
| --- | --- | --- |
| LangChain | Beta | Duck-typed wrapper for common tool interfaces. |
| LangGraph | Beta | Wraps tool-node style execution. |
| CrewAI | Beta | Wraps callable tools. |
| OpenAI Agents SDK | Beta | Callback-oriented tool authorization. |
| MCP | Experimental | Intercepts `tools/call`; normalize payloads carefully. |
| PydanticAI | Experimental | Callable wrapper pattern. |
| LlamaIndex | Experimental | Callable or `call`/`acall` wrappers. |
| AutoGen | Experimental | Tool registry wrapper pattern. |
