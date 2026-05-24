# Changelog

## Versioning and maturity

CapFence is pre-1.0 public beta infrastructure. Until `1.0`, minor versions may refine public APIs, policy schema details, and integration wrappers. The local YAML policy runtime is the most mature surface; framework adapters, starter policy packs, external policy backends, and supply-chain automation should be validated in the target environment before production use.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.3] - 2026-05-24

### Added
- Policy development CLI commands: `capfence policy test`, `capfence policy explain`, and `capfence policy diff`.
- Starter policy packs for shell, filesystem/MCP, SQL, payments, and Kubernetes boundaries.
- Policy fixture runner and explain helpers for repeatable policy testing.
- Optional policy backend interfaces with local YAML and OPA HTTP backend scaffolding.
- Security architecture, product positioning, external policy backend, policy pack, and release checklist documentation.
- CI policy fixture validation and release provenance workflow examples.

### Changed
- Public maturity language now consistently describes CapFence as pre-1.0 public beta infrastructure.
- Package artifacts now include bundled starter policy packs.
- Policy explain output now reports explicit `default_deny` internally while CLI fixtures display it as `deny`.

### Fixed
- Conditional policy rules no longer fall back to capability-only allow matching when no condition matches.
- Shell baseline pack no longer permits broad `cat ./...` access that could expose workspace secrets.

## [0.7.0] - 2026-05-15

### Changed
- **Project renamed from ShadowAudit to CapFence.** All package names, imports, CLI commands, class names, and documentation updated. The PyPI package is now `capfence`.
- Repository URLs updated to `github.com/capfencelabs/capfence`.

## [0.6.2] - 2026-05-15

### Added
- `capfence check-policy` command for validating YAML policy files.
- Policy support for `contains`, `amount_gte`, `amount_lt`, `amount_lte`, `path_prefix`, caller-depth comparisons, and legacy `rules` starter-policy schemas.
- Demo walkthrough, demo cast, and demo script covering scan, assess, gate enforcement, simulate, and verify workflows.
- Recipes section with copy-paste policy patterns and integrations for PydanticAI, LlamaIndex, and AutoGen.
- Compatibility matrix for supported framework adapters.

### Changed
- README and docs homepage now position CapFence around deterministic runtime authorization, rollout, limitations, and proof-oriented workflows.
- Repository URLs now point to the `capfencelabs/capfence` namespace.
- Local package metadata now matches the PyPI `0.6.2` release line.

### Fixed
- Policy load and validation failures now fail closed during gate evaluation.
- Audit write failures now fail closed in enforce mode.
- Policy schema documentation now matches implemented behavior.

## [0.5.0] - 2026-05-11

### Added
- **Multi-agent flow tracer** (`capfence.flow.FlowTracer`). Records data flows between agents and propagates trust downward — UNTRUSTED data feeding a SYSTEM-trust agent contaminates that agent's effective trust. Reverse index keeps `annotate()` O(1) per source agent. Thread-safe via internal `RLock`. Configurable `max_edges` with FIFO eviction.
- **Gate observe mode** (`Gate(mode="observe")`). Logs every decision without blocking. `result.metadata["would_have_blocked"]` reports what enforce mode would have done. Use for staged rollout before turning enforcement on.
- **Gate bypass context manager** (`gate.bypass(agent_id, reason="...")`). Per-agent stack-based override with mandatory non-empty audit-trail reason. Thread-safe; reason is stored in the audit log.
- **`capfence tune` CLI command**. Reads recent gate decisions, groups by risk category, and suggests RAISE / LOWER / OK threshold adjustments based on block rate vs. average score.
- **`evaluate_async()` on `Gate`**. Async wrapper that runs the synchronous scoring + SQLite I/O on the default thread-pool executor so an event loop is never blocked.
- **`arun()` / `ainvoke()` on framework adapters**. `CapFenceTool` (LangChain), `CapFenceCrewAITool`, `CapFenceToolNode` (LangGraph) gained async variants that use `evaluate_async` and forward to the wrapped tool's async method when present. OpenAI Agents SDK and MCP adapters now use `evaluate_async` internally so the gate no longer blocks the event loop.
- **Unified exception hierarchy** in `capfence.errors`. `CapFenceError` base class with `AgentActionBlocked`, `ConfigurationError`, `AuditError`, `TaxonomyError`, `GatewayError` subclasses. `AgentActionBlocked` is now a single class re-exported by every framework module, so `except capfence.AgentActionBlocked` catches blocks from any adapter.
- **Expanded taxonomies**: `financial.json` grew from 14 to 32 categories (loan_origination, KYC, AML, sanctions, FX, card_control, open_banking_consent, etc.). New `financial_crypto.json` (18 categories) and `healthcare.json` (17 categories).
- **Tamper-evidence demo** (`examples/tamper_demo.py`). Records 6 gate decisions, corrupts a row directly in SQLite, verifies the chain breaks, restores and re-verifies.
- **Production-style fintech agent** (`examples/fintech_payment_agent.py`). 4 payment tools wrapped with the Gate; demonstrates idempotency keys, exponential backoff, and gate-driven early returns.
- **Labelled test corpus** (`tests/corpus/`). 130 traces (50 benign / 50 risky / 30 edge cases) in JSONL with `evaluate.py` runner.
- **Scorer benchmark** (`benchmarks/scorer_benchmark.py`). Compares KeywordScorer, RegexASTScorer, AdaptiveScorer on 10K synthetic traces with TPR/FPR/F1/latency. `benchmarks/README.md` documents how to read the results honestly.
- **Threat model doc** (`docs/THREAT_MODEL.md`). Attack surface diagram, what CapFence catches, what it misses (G1–G9), recommended additional layers, false-positive runbook.
- **Top-level `__version__`** exposed via `capfence.__version__`.
- **`py.typed` marker**. Package now ships type information for mypy / pyright consumers.

### Changed
- **Package classifier bumped to `Development Status :: 4 - Beta`**; added `Topic :: Security` and `Typing :: Typed` classifiers.
- **`Gate._bypass_stack` is now thread-safe** via an internal `threading.RLock`; concurrent agents can share one `Gate` instance.
- **`FlowTracer` is now thread-safe**. Previous docstring claim "use one instance per thread" removed.
- **`Gate.__init__` and `Gate.bypass`** now raise `ConfigurationError` instead of bare `ValueError` (subclass of `ValueError` for backward compatibility).
- **MCP gateway** now raises `GatewayError` instead of bare `RuntimeError` (subclass of `RuntimeError` for backward compatibility).
- README rewritten with new features section (observe mode, FlowTracer, expanded taxonomies, threat model link); test badge updated to 226 passing.
- Tests: 205 → 226 passing.

### Fixed
- Deduplicated `would_have_blocked` metadata assignment in `Gate.evaluate()`.
- Removed dead `payload` parameter from `FlowTracer.annotate()` signature.
- Replaced custom `_hash_data()` in FlowTracer with `compute_payload_hash` for consistency.
- Hoisted `import statistics` / `from collections import defaultdict` in `cli.py` from inside `tune()` to module level.

## [0.4.1] - 2026-05-10

### Changed
- README overhaul: hero section with three AGT differentiators, collapsed feature list into 6 categories, honest positioning docs.
- Added CHANGELOG.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, docs/CLI.md, docs/FEATURES.md, docs/POSITIONING.md.
- Added GitHub issue templates and pull request template.

### Fixed
- Removed unused `pytest` import in `tests/test_mcp.py` (CI ruff failure).
- Added `mypy` `ignore_missing_imports` for `cryptography` and `capfence._native` (CI mypy failure).
- Fixed README Python API example to match real `Gate.evaluate()` signature.
- Fixed ASCII architecture diagram alignment.

## [0.4.0] - 2026-05-08

### Added
- **Hash-chained, tamper-evident audit log** (`capfence/core/chain.py`). Every audit entry links to the previous via SHA-256. Modifying any row invalidates the chain. Verified via `capfence verify`.
- **Optional Ed25519 signing of audit entries** (`capfence/core/keys.py`). Generate keypairs, sign each entry, and verify authenticity cryptographically. Falls back to HMAC-SHA256 when `cryptography` is not installed.
- **Hardened Regex+AST scorer** (`capfence/core/scorer.py`). `RegexASTScorer` adds whole-word regex matching and Python AST analysis for dangerous constructs (`os.system`, `subprocess.call`, `eval`, `exec`).
- **OWASP Agentic Top 10 coverage matrix** (`capfence/assessment/owasp.py`). Static mapping of CapFence controls to OWASP Agentic AI Top 10 risks. Generate HTML reports via `capfence owasp`.
- **MCP gateway server** (`capfence/mcp/gateway.py`). Stdio proxy that intercepts MCP tool calls through the CapFence Gate. JSON-RPC parsing with Content-Length protocol.
- **MCP in-process adapter** (`capfence/mcp/adapter.py`). `CapFenceMCPSession` wraps an existing MCP client session with CapFence gating for async tool calls.
- **LangGraph integration** (`capfence/framework/langgraph.py`). `CapFenceToolNode` replaces LangGraph `ToolNode` with automatic gate enforcement on every tool invocation.
- **OpenAI Agents SDK integration** (`capfence/framework/openai_agents.py`). `CapFenceOpenAITool` wraps OpenAI Agents SDK tools with deterministic gate evaluation.
- **EU AI Act Annex IV evidence pack generator** (`capfence/assessment/eu_ai_act.py`). Generates structured JSON + HTML evidence packs for regulatory submission. Covers risk management, cybersecurity, data governance, and technical documentation.
- **Plaid taxonomy pack** (`capfence/taxonomies/financial_plaid.json`). 10 Plaid-specific risk categories: auth, balance, transactions, identity, income, transfer, link token, item management, liabilities, investments.
- **Opt-in telemetry client** (`capfence/telemetry/client.py`). Async fire-and-forget exporter for hashed metadata only. Disabled by default; enable via `CAPFENCE_TELEMETRY=1`.
- **CLI commands**: `capfence verify` (audit log integrity), `capfence owasp` (coverage matrix), `capfence eu-ai-act` (evidence pack generation).
- **9 new runnable examples** in `examples/` covering all v0.4.0 features, plus `examples/run_all_examples.py` test runner.
- **11 new test files** bringing total to 205 tests (1 skipped for optional `pytest-asyncio`).
- **Demo project** (`capfence-demo/`) — realistic fintech agent with 8 tools, 2 intentionally ungated, for end-to-end scanner validation.

### Changed
- **README overhaul**: collapsed 14-item feature list into 6 grouped categories; added Testing section; updated Examples table with all 12 examples.
- **Architecture diagram**: updated audit-log box to "Hash-chained + Ed25519".
- **Project Status**: trimmed from 14 bullets to 6 grouped categories.
- **Cross-file wrapper detection**: two-pass scanner (`_collect_all_wrappers` then `scan_file`) correctly detects tools wrapped in a different file from their definition.
- **Taxonomy cache safety**: `TaxonomyLoader.load()` now returns `copy.deepcopy(data)` to prevent shared mutable state poisoning.
- **Scorer performance**: added `@functools.lru_cache` for regex pattern compilation in `RegexASTScorer`.

### Fixed
- **Timing attack vulnerability** in fallback signature verification: replaced `==` with `hmac.compare_digest` in `capfence/core/keys.py`.
- **Private key race condition**: `generate_keypair()` now uses atomic `os.open()` with mode `0o600` instead of `write_text()` + `os.chmod()`.
- **Taxonomy cache poisoning**: `Gate.evaluate()` now deep-copies taxonomy entries before mutation.
- **MCP unbounded Content-Length**: enforced `MAX_MESSAGE_SIZE` (10MB) to prevent memory exhaustion.
- **MCP stderr thread race**: `_drain_stderr` now acquires `self._lock` when accessing `self._proc`.
- **Telemetry worker race**: `TelemetryClient.start()` now guarded by `asyncio.Lock` to prevent duplicate worker tasks.
- **EU AI Act path traversal**: `write_html()` and `write_json()` now reject paths containing `..` components.
- **CLI version consistency**: extracted `__version__` constant; fixed hardcoded `0.3.0` in assessment context.
- **Hash chain missing-key validation**: `verify_chain_from_rows()` now gracefully handles malformed DB rows instead of raising `KeyError`.

### Security
- See Fixed section above for security-related fixes.

## [0.3.3] - 2026-05-07

### Added
- `default="."` on `capfence check` path argument so `capfence check` works without explicit path.

### Fixed
- Cross-file wrapper detection: tools defined in one file and wrapped in another are now correctly detected as gated (two-pass scanning).

## [0.3.2] - 2026-05-07

### Fixed
- README version badge and PyPI description sync.
- CI workflow with release assets.

## [0.3.1] - 2026-05-07

### Added
- `capfence check --output report.html` for HTML report generation from static scan.
- `--fail-on-ungated` flag for CI/CD integration.

### Fixed
- Scanner false positives on non-tool classes.

## [0.3.0] - 2026-05-07

### Added
- Initial PyPI release.
- Core Gate with keyword-based scoring and configurable thresholds.
- SQLite-backed audit log (append-only).
- LangChain and CrewAI adapters.
- Static scanner (`capfence check`) for detecting ungated tool classes.
- Assessment reporter with Jinja2 HTML reports.
- Trace simulator (`capfence simulate`) for replaying agent execution traces.
- Interactive taxonomy builder (`capfence build-taxonomy`).
- Three starter taxonomies: general, financial, legal.
- Cloud client hook (legacy, not used in OSS path).

[Unreleased]: https://github.com/capfencelabs/capfence/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/capfencelabs/capfence/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/capfencelabs/capfence/compare/v0.5.0...v0.6.2
[0.4.0]: https://github.com/capfencelabs/capfence/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/capfencelabs/capfence/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/capfencelabs/capfence/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/capfencelabs/capfence/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/capfencelabs/capfence/releases/tag/v0.3.0
