# CapFence Threat Model

This document describes what CapFence catches, what it doesn't, where it falls short, and what additional layers a production deployment requires. It is written for security engineers, compliance auditors, and architects evaluating CapFence for regulated workloads.

---

## What CapFence Is

CapFence is a **fail-closed, rule-based runtime gate** for AI agent tool calls. It runs synchronously before each tool call executes, evaluates the call's payload against a risk taxonomy, and either permits or blocks the call. It also maintains a tamper-evident audit log of every decision.

CapFence is **not** a general-purpose firewall, LLM input/output filter, or intrusion detection system. It is purpose-built for the specific problem of agentic drift: an LLM-driven agent taking a tool action that the operator did not intend.

---

## Attack Surface

The agent pipeline has five trust boundaries CapFence addresses:

```
[User/LLM Prompt] → [Agent Orchestrator] → [Tool Call Payload] ←→ [CapFence Gate] → [Tool Execution]
                                                                         ↓
                                                                   [Audit Log DB]
                                                                         ↓
                                                                   [Evidence Pack]
```

1. **Tool call payload** — the dict passed to each tool. CapFence inspects this.
2. **Risk taxonomy** — the configured thresholds. CapFence enforces these.
3. **Audit log** — the SQLite DB of decisions. CapFence signs and chains these.
4. **Gate process** — the Python process running the gate. CapFence cannot protect itself from a compromised runtime.
5. **Cross-agent boundaries** — data flowing from one agent to another. See [Gap 6](#what-capfence-does-not-catch).

---

## What CapFence Catches

### 1. Direct keyword-based risk signals

A payload containing risk keywords from the configured taxonomy is flagged. For example, in the financial taxonomy, `create_payout`, `wire`, `bulk`, and `disburse` are high-risk keywords for the `stripe_payout` category. Any payload containing enough of these words to exceed the category delta threshold is blocked.

**Detection mechanism:** KeywordScorer (substring match) or RegexASTScorer (whole-word regex + AST analysis).

**Coverage:** Good for well-named payloads where LLM-generated field names or values mirror API semantics.

### 2. Python AST patterns in code-execution payloads

When a payload field contains Python source code (e.g., a `code` or `script` field in a code-execution tool), CapFence's `RegexASTScorer` parses the AST and flags dangerous constructs: `exec`, `eval`, `subprocess.run`, `os.system`, `__import__`, and similar.

**Detection mechanism:** Python `ast.parse()` + walk for dangerous node types.

**Coverage:** Catches common prompt-injection → code-execution chains. Does not catch obfuscated code or non-Python execution.

### 3. Behavioral drift via K/V tracking

The `AgentStateStore` maintains a decision history per agent. The K metric (decision velocity) and V metric (decision variance) allow future adaptive scorers to detect anomalous patterns: an agent making 50 payment calls in 10 minutes when the baseline is 3/hour.

**Detection mechanism:** K/V state stored in SQLite, used by the AdaptiveScorer.

**Coverage:** OSS version uses these metrics for logging. Enterprise native binary uses them for active blocking. The open-source AdaptiveScorer applies RegexAST scoring with state context.

### 4. Tamper detection in audit log

Every audit log entry is SHA-256 hashed over its content + the previous entry's hash. Any modification to a stored entry (changing a decision from `fail` to `pass`, altering a risk_score, deleting a row) causes `capfence verify` to report the chain break with the exact entry ID.

**Detection mechanism:** Hash chain. Run `capfence verify --audit-log audit.db`.

**Coverage:** Detects post-hoc modification. Does NOT prevent modification — that requires append-only storage (see below).

### 5. Codebase-level ungated tool detection

`capfence check ./src` performs static analysis on Python source and identifies tool classes that are not wrapped with CapFence. This catches the "forgot to add a gate" deployment error before it reaches production.

**Detection mechanism:** AST scan for tool class patterns by framework (LangChain, CrewAI, OpenAI Agents, LangGraph, MCP).

### 6. EU AI Act / OWASP Agentic Top 10 compliance evidence

`capfence eu-ai-act`, `capfence check`, policy fixture results, replay output,
and audit verification can be used as machine-readable evidence artifacts.
These are **evidence generators**, not detectors — they document what controls
are present, not whether an attack is occurring.

---

## What CapFence Does Not Catch

These are gaps by design, by technical limitation, or because the threat requires additional layers. We document them honestly so deployments can compensate.

### G1 — Semantically dangerous payloads with no keyword match

A payload like `{"recipient": "attacker_account_123", "qty": 50000}` for a high-value transfer tool contains no taxonomy keywords. The keyword scorer returns 0.0, below any threshold, and the call passes. This is the core false-negative scenario for keyword-based scoring.

**Mitigation:** Tune policy conditions and taxonomy keywords to cover your
specific API's field names. Validate changes with policy fixtures and replay
before enforcing.

**Out-of-scope for CapFence:** Semantic understanding requires an LLM-based evaluator (e.g., a secondary guard LLM). CapFence is intentionally LLM-free to guarantee determinism and zero-latency.

### G2 — Prompt injection that does not produce risky tool calls immediately

A prompt injection that instructs the agent to exfiltrate data slowly over many small, individually-safe transactions is not caught by per-call evaluation. CapFence evaluates calls in isolation; it has no concept of multi-call sequences that are collectively risky.

**Mitigation:** K/V behavioral tracking (enterprise) can detect velocity anomalies. For now, set low amount thresholds and low-value transaction limits at the API level.

### G3 — Cross-agent trust boundary violations

Agent A's output becomes Agent B's tool call input without re-evaluation. If Agent A is a low-trust external agent (processing user-supplied content) and its output reaches Agent B's payment tool without trust annotation, CapFence evaluates the payload at face value without knowing it originated from an untrusted source.

**Mitigation:** Use the `capfence.flow.FlowTracer` (see `capfence/flow/`) to annotate cross-agent data flows with trust labels. This is available in v0.5.0+. Until then, treat all payloads as untrusted.

### G4 — Attacks that modify the gate itself

If an attacker can modify the Python process memory, inject code into the gate module, patch `Gate.evaluate`, or replace the taxonomy file at rest, all protection is bypassed. CapFence assumes it runs in a trusted execution environment.

**Mitigation:** Standard supply chain hygiene (pinned dependencies, signed releases, immutable infrastructure). CapFence's own releases are signed; verify before deploying.

### G5 — Audit log modification before detection

The hash chain detects tampering after the fact. An attacker with write access to the SQLite file could delete the file entirely, or replace it with a fresh chain. `capfence verify` would report the new chain as valid.

**Mitigation:** Store the audit log on append-only storage: S3 with Object Lock, GCS with retention policy, a WORM drive, or a blockchain anchor (the `sign_entries=True` flag + external key storage). The hash chain is evidence of what was logged; it requires write-once infrastructure to be tamper-proof end-to-end.

### G6 — Non-Python agentic runtimes

CapFence is Python-only. Java, Node.js, Go, or Rust agent runtimes are not covered.

### G7 — LLM-level attacks that bypass tool calling

A sufficiently capable adversarial prompt might cause an LLM to construct a system prompt that instructs another LLM to perform risky actions through a separate, unmonitored channel. CapFence only gates tool calls that flow through the configured gate instance.

### G8 — False negatives in the AST scanner

The AST scanner uses a fixed list of dangerous function names (`exec`, `eval`, `subprocess.run`, etc.). An attacker using `__builtins__['exec']`, `importlib.import_module`, or a custom loader can bypass the AST check. The AST scanner is a detection-in-depth layer, not a sandbox.

### G9 — Side-channel information leakage

CapFence logs `payload_hash` (a hash of the full payload) not the payload itself. An attacker with access to both the payload and the audit log can confirm a match. This is intentional: the hash commits to the content without storing it, enabling verification without exposure.

---

## Recommended Additional Layers

CapFence is one layer in a defense-in-depth stack. For regulated workloads (EU AI Act high-risk, PCI-DSS, SOX), we recommend:

| Layer | Tool / Approach |
|---|---|
| Input sanitisation | Structured LLM output schemas (Pydantic); reject unstructured tool calls |
| Output guardrails | NeMo Guardrails / LlamaFirewall on LLM output before tool call construction |
| Semantic risk evaluation | Secondary guard LLM as a pre-gate evaluator for ambiguous payloads |
| Append-only audit storage | S3 Object Lock, WORM drive, or blockchain anchor for the SQLite file |
| Human-in-the-loop for irreversible actions | Approval workflows for wire transfers, bulk payouts, account closures |
| Rate limiting | Per-agent and per-category rate limits at the API gateway layer |
| Network egress filtering | Block agent process from reaching unexpected external endpoints |
| Dependency pinning | Pin and sign all CapFence releases; run `pip-audit` on your venv |
| Cross-agent flow tracing | `capfence.flow.FlowTracer` for multi-agent deployments (v0.5.0+) |

---

## False-Positive Runbook

When CapFence blocks a legitimate tool call:

1. **Check the audit log** — `capfence verify --audit-log audit.db` to confirm the log is intact.
2. **Inspect the blocked call** — Use `capfence logs --audit-log audit.db --json` and the blocked request payload from your application logs.
3. **Validate a policy change** — Add or update policy fixture cases, then run `capfence policy test`.
4. **Replay historical traffic** — Run `capfence replay <trace.jsonl> --policy <candidate-policy.yaml>` before rolling out.
5. **Roll out carefully** — Use approval requirements for ambiguous high-impact actions until the policy behavior is well understood.

---

## Security Contact

Report vulnerabilities to: security@capfence.dev (or open a GitHub Security Advisory on the repository). We follow responsible disclosure and aim to respond within 72 hours.

See [SECURITY.md](../SECURITY.md) for the full disclosure policy and PGP key.
