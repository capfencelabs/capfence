# Internal Components

CapFence is organized around a small runtime gate and supporting infrastructure for audit, replay, integrations, and reporting.

```text
Agent Framework Adapter
        │
        ▼
Core Gate Engine
        │
        ├─ Capability Mapper
        ├─ Policy Engine
        ├─ Risk Evaluation
        ├─ Enforcement FSM
        └─ Audit Logger
```

## Core gate

The gate is the runtime enforcement primitive. It receives an agent ID, capability, task context, risk category, and payload, then returns a deterministic decision.

## Policy engine

The policy engine evaluates explicit policy-as-code rules such as `allow`, `deny`, and `require_approval`.

## Audit logger

The audit logger records decisions in SQLite with hash chaining and optional signatures. Ed25519 signatures require the `capfence[crypto]` extra.

## Adapters

Adapters let CapFence sit in front of common agent tool systems:

- LangChain
- LangGraph
- CrewAI
- OpenAI Agents SDK
- MCP
- Direct Python tools

## Assessment and reporting

The scanner, simulator, and reporting modules support CI checks, replay, compliance reports, and governance evidence generation.
