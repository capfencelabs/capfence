# Agent Authority Model

CapFence is built around a simple security principle:

> The model should produce intent, not hold authority.

An AI agent may propose an action, but it should not directly hold the credentials or execution path needed to mutate production systems.

## Bad Architecture

Agent has direct authority:

```txt
Agent -> Tool with credentials -> Production system
```

In this model, prompts become the only practical control. If the model is manipulated, confused, or overconfident, the tool may still execute.

## CapFence Architecture

Agent proposes; CapFence authorizes; executor acts:

```txt
Agent -> Proposed action -> CapFence -> Gated executor -> Production system
```

The executor owns the real credentials. The agent does not.

## Why This Matters

Prompt guardrails influence model behavior. CapFence controls execution authority.

CapFence is only authoritative when side-effectful tools are reachable through a CapFence-gated executor.
