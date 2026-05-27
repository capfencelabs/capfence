# Why Not Just Sandboxing, OPA, Or Prompt Guardrails?

CapFence is not a replacement for sandboxing, OPA, or prompt guardrails. It sits at the agent tool-call boundary and decides whether a requested side effect may execute.

| Control | Best at | Why CapFence is still useful |
| --- | --- | --- |
| Sandboxing | Limiting what a process can touch after it starts. | CapFence blocks or routes the tool call before execution, with policy reasons and audit records. |
| OPA | Centralized policy decisions for normalized inputs. | CapFence normalizes agent actions, provides local policy ergonomics, and can delegate to OPA when that is the right backend. |
| Prompt guardrails | Steering model behavior and reducing unsafe requests. | Prompts are guidance, not authorization. CapFence enforces a deterministic decision outside the model. |

Use them together: prompts reduce bad requests, CapFence authorizes the side effect, OPA can serve as an external policy backend, and sandboxing limits blast radius if execution proceeds.
