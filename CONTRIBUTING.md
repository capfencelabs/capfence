# Contributing to CapFence

Thank you for your interest in contributing to CapFence. As a foundational runtime authorization layer for AI agents, we prioritize deterministic behavior, security, and enterprise reliability above all else. 

This document outlines the engineering standards and workflows for contributing to the core engine, framework adapters, and policy modules.

## Engineering Philosophy

1. **Fail-Closed by Default**: Any error in evaluation, configuration parsing, or network interruption must result in a blocked execution. We do not degrade to "allow".
2. **Deterministic Governance**: We do not use LLMs in the critical path for risk evaluation. All new evaluation logic must be mathematically or structurally deterministic (e.g., regex, AST parsing, deterministic state machines).
3. **Air-Gap Compatibility**: No core feature may require outbound internet access.
4. **Sub-millisecond Latency**: Overhead introduced by the gate must be negligible.

## Development Setup

```bash
git clone https://github.com/capfencelabs/capfence.git
cd capfence
python -m pip install --upgrade pip
pip install --require-hashes -r requirements-dev.txt
pip install -e . --no-deps
```

## Pull Request Pipeline

We maintain a strict CI/CD pipeline for all enterprise-grade merges:

1. **Branching Strategy**: Branch from `main`. Use descriptive prefixes: `core/`, `adapter/`, `policy/`, `docs/`.
2. **Test Coverage**: Every logic branch must be tested. We require edge-case testing, especially for bypass logic and failure modes.
3. **Local Validation**:
   - `pytest tests/ -q`
   - `mypy --strict capfence/`
   - `ruff check capfence/ tests/`
4. **Documentation**: Updates to APIs must be reflected in `docs/architecture.md` and `README.md`.
5. **Review**: A core maintainer will review the PR for security implications, fail-closed enforcement, and performance regressions.

## Adding Policies

If you are contributing to the standard policy taxonomy (under `policies/` or `capfence/taxonomies/`):
- Ensure keywords or regexes use whole-word boundaries where applicable to minimize false positives.
- Clearly document the threat vector the policy addresses.
- Provide a unit test demonstrating both the allowed execution and the blocked execution.

## Adding Framework Adapters

When integrating a new agent framework (e.g., LlamaIndex):
1. Create `capfence/framework/<framework>.py`.
2. Implement a transparent proxy that extracts the tool invocation payload.
3. Ensure the `Gate.evaluate()` result directly controls the upstream execution.
4. Add a minimal, runnable example to `examples/<framework>/`.

## Security

Please refer to [SECURITY.md](SECURITY.md) for vulnerability reporting. Do not open public issues for security vulnerabilities.
