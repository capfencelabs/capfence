# CapFence Feature Reference

This document lists the current repository feature surface. For command syntax,
see [`docs-dev/CLI.md`](CLI.md) and [`docs/reference/cli.md`](../docs/reference/cli.md).

## Runtime Authorization

`ActionRuntime` evaluates `ActionEvent` objects against deterministic YAML
policies before a side effect reaches the downstream tool. Policy outcomes are
`allow`, `deny`, `require_approval`, `warn`, or fail-closed default deny.

Implemented in:

- [`capfence/core/runtime.py`](../capfence/core/runtime.py)
- [`capfence/core/capabilities.py`](../capfence/core/capabilities.py)
- [`capfence/core/policy.py`](../capfence/core/policy.py)

## Audit Chain and Signing

Every runtime decision can be recorded in SQLite with a SHA-256 hash link to the
previous entry. Modifying a row breaks the chain.

`AuditLogger(sign_entries=True)` also stores entry signatures. Install
`capfence[crypto]` for Ed25519 signatures via `cryptography`; the no-crypto
fallback is compatibility-only and is not Ed25519-equivalent. `capfence verify`
checks the hash chain and verifies stored signatures when present.

Implemented in:

- [`capfence/core/audit.py`](../capfence/core/audit.py)
- [`capfence/core/chain.py`](../capfence/core/chain.py)
- [`capfence/core/keys.py`](../capfence/core/keys.py)

## Policy Development

CapFence supports local YAML policies, policy inheritance, fixture tests,
policy explanations, and policy diffs.

Commands:

- `capfence check-policy`
- `capfence policy test`
- `capfence policy explain`
- `capfence policy diff`

Implemented in:

- [`capfence/core/policy.py`](../capfence/core/policy.py)
- [`capfence/core/policy_testing.py`](../capfence/core/policy_testing.py)
- [`capfence/cli.py`](../capfence/cli.py)

## Framework Adapters

The package ships importable wrappers for:

- LangChain: `CapFenceTool`
- LangGraph: `CapFenceToolNode`
- OpenAI Agents SDK: `CapFenceOpenAITool`
- CrewAI: `CapFenceCrewAITool`
- AutoGen: `CapFenceAutoGenTool`
- LlamaIndex: `CapFenceLlamaIndexTool`
- PydanticAI: `CapFencePydanticTool`
- MCP stdio gateway: `MCPGatewayServer`
- MCP in-process session: `CapFenceMCPSession`

The wrappers are duck-typed where possible so the base CapFence install does not
force every framework dependency.

## Static Scanner

`capfence check` parses Python source with the AST module, identifies common
agent tool definitions, and flags tools that are not wrapped with CapFence.
It supports strict CI failure modes and JSON output.

Implemented in [`capfence/check.py`](../capfence/check.py).

## Replay and Evidence

`capfence replay` replays JSON/JSONL traces for deterministic incident review or
candidate-policy simulation.

`capfence eu-ai-act` produces a technical evidence report from static scan
results and an optional audit log. It is governance evidence, not a legal
compliance determination.

Implemented in:

- [`capfence/core/replay.py`](../capfence/core/replay.py)
- [`capfence/cli.py`](../capfence/cli.py)

## Taxonomies and Scoring

CapFence includes bundled risk taxonomies and deterministic scorers for keyword
and regex/AST-based payload inspection. These are support utilities for
classification and reporting, not LLM-based judges.

Implemented in:

- [`capfence/core/taxonomy.py`](../capfence/core/taxonomy.py)
- [`capfence/core/scorer.py`](../capfence/core/scorer.py)
- [`capfence/taxonomies`](../capfence/taxonomies)
