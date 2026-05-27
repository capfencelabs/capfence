# CapFence Repo Hardening Build Plan

This plan turns the repository review findings into an implementation sequence.
The goal is to make the public package claims, shipped code, docs, and release
checks agree before the next release.

## Target Outcome

CapFence should be publishable as a credible beta package where:

- Public README/API claims match importable modules and runnable examples.
- Security and audit claims are technically precise.
- Contributor docs describe the current codebase and commands.
- CI/release checks catch the same problems locally and remotely.
- Generated local artifacts do not obscure repository state.

## Phase 1: Fix Public API and Adapter Claims

Priority: P0

Problem:

The README and examples advertise adapters that are not present as importable
source modules. This creates immediate `ModuleNotFoundError` failures for users.

Work items:

- Decide the adapter truth table for the next release:
  - Keep as supported: LangChain, LangGraph, OpenAI Agents SDK, MCP.
  - Implemented as lightweight wrappers: CrewAI, AutoGen, LlamaIndex, PydanticAI.
- Update `README.md` maturity table to match shipped modules.
- Update or remove examples that import missing adapters.
- Update optional dependencies in `pyproject.toml` only for adapters that exist.
- Add import smoke tests for every adapter mentioned in public docs.

Acceptance criteria:

- Every adapter listed as Beta or Experimental has an importable module or a
  clearly labeled non-wrapper demo.
- `python3 - <<'PY' ... import capfence.framework.<adapter> ... PY` succeeds for
  all claimed adapters.
- `python3 -m pytest tests/test_framework_* tests/test_mcp.py -q` passes.
- README no longer overstates missing adapter support.

Suggested verification:

```bash
python3 -m pytest tests/test_framework_* tests/test_mcp.py -q
python3 -m pytest -q
python3 -m ruff check capfence tests examples
python3 -m mypy capfence
```

## Phase 2: Tighten Audit Signing and Security Claims

Priority: P0

Problem:

The code exposes Ed25519 signing helpers, but `cryptography` is optional and the
fallback is not Ed25519-equivalent. Audit verification currently checks the hash
chain, not stored signatures.

Work items:

- Decide production signing posture:
  - Option A: make `cryptography` a runtime dependency.
  - Option B: add `capfence[crypto]` and clearly document unsigned/fallback mode.
- Add signature verification to audit validation when signatures are present.
- Make fallback behavior explicit in docs and CLI output.
- Update README/docs language from broad "cryptographically signed" claims to
  precise statements about hash chaining, optional signatures, and dependencies.
- Add tests for:
  - Ed25519 signing and verification with valid signature.
  - Tampered signed entry fails verification.
  - Fallback signatures are not treated as Ed25519 when `cryptography` is present.

Acceptance criteria:

- `AuditLogger.verify()` or a companion verification path detects invalid
  signatures for signed audit logs.
- Docs distinguish hash-chain integrity from digital signatures.
- Release metadata does not imply production-grade signatures without the needed
  dependency path.

Suggested verification:

```bash
python3 -m pytest tests/test_core_keys.py tests/test_core_chain.py -q
python3 -m pytest -q
python3 -m ruff check capfence tests
python3 -m mypy capfence
```

## Phase 3: Refresh Contributor and Internal Docs

Priority: P1

Problem:

`docs-dev/TESTING_GUIDE.md` contains stale version numbers, expected test counts,
old module names, and CLI commands that do not match the current package.

Work items:

- Rewrite `docs-dev/TESTING_GUIDE.md` around current v0.8.x commands.
- Remove references to deleted APIs such as `capfence.core.gate`.
- Replace stale example paths with current `examples/core_concepts/...` paths.
- Align contributor commands with CI:
  - `python3 -m pytest -q`
  - `python3 -m ruff check capfence tests`
  - `python3 -m mypy capfence`
  - `python3 -m build`
  - `python3 -m twine check dist/*`
- Update `CONTRIBUTING.md` if it still asks for commands stricter than CI without
  explaining the difference.

Acceptance criteria:

- A new contributor can follow the testing guide without hitting missing commands.
- Expected test counts are removed or described as examples, not fixed truth.
- Internal docs do not mention old public APIs as current usage.

Suggested verification:

```bash
python3 -m pytest -q
python3 -m ruff check capfence tests
python3 -m mypy capfence
```

## Phase 4: Split CLI Into Maintainable Modules

Priority: P1

Problem:

`capfence/cli.py` is large and mixes command registration, business logic, and a
large embedded HTML template.

Work items:

- Introduce a small CLI package layout, for example:
  - `capfence/cli.py` as the Click entry point.
  - `capfence/cli_commands/check.py`
  - `capfence/cli_commands/policy.py`
  - `capfence/cli_commands/audit.py`
  - `capfence/cli_commands/reports.py`
- Move report HTML into a package template file or a focused renderer module.
- Source CLI version from `capfence.__version__` instead of duplicating it.
- Keep command names and options backward-compatible unless a breaking change is
  intentionally documented.
- Add CLI regression tests for the moved commands.

Acceptance criteria:

- `capfence --version` still reports the package version.
- Existing tested CLI commands keep the same output shape where tests depend on it.
- `capfence/cli.py` becomes a thin registration layer.

Suggested verification:

```bash
python3 -m pytest tests/test_cli_taxonomy.py tests/test_cli_eu_ai_act.py tests/test_policy_pack_cli.py -q
python3 -m pytest -q
python3 -m ruff check capfence tests
python3 -m mypy capfence
```

## Phase 5: Repository Hygiene and Release Checks

Priority: P2

Problem:

The workspace accumulates ignored local artifacts, and `.gitignore` currently
ignores broad Markdown patterns that can hide useful repo files such as GitHub
templates.

Work items:

- Revisit `.gitignore` Markdown rules:
  - Keep private strategy docs ignored.
  - Explicitly unignore `.github/**/*.md` if templates should be tracked.
  - Consider moving internal private notes outside the repo instead of broad
    root-level ignores.
- Clean local generated artifacts:
  - `__pycache__/`
  - `.DS_Store`
  - `.pytest_cache/`
  - `.ruff_cache/`
  - `.mypy_cache/`
  - stale `dist/`
  - local demo databases
  - generated `site/`
- Add Makefile targets or a nox/tox task for common checks.
- Ensure release checks remove stale `dist/` before build and only validate new
  artifacts.
- Add a local "release dry run" command that mirrors CI.

Acceptance criteria:

- `git status --short --ignored` is understandable and does not hide important
  tracked-candidate files.
- Build verification checks only freshly generated artifacts.
- Maintainers have one local command for the full pre-release gate.

Suggested verification:

```bash
rm -rf dist build site .pytest_cache .ruff_cache .mypy_cache
find . -name '__pycache__' -type d -prune -exec rm -rf {} +
python3 -m pytest -q
python3 -m ruff check capfence tests
python3 -m mypy capfence
python3 -m build
python3 -m twine check dist/*
git status --short --ignored
```

## Recommended Execution Order

1. Phase 1: adapter claims and examples.
2. Phase 2: audit signing precision.
3. Phase 3: docs refresh.
4. Phase 4: CLI split.
5. Phase 5: hygiene and release command polish.

Phases 1 and 2 should land before any public release. Phases 3 and 5 are small
enough to do alongside them. Phase 4 is larger and can be a separate refactor
after the public behavior is made accurate.

## Release Readiness Gate

Run this before tagging the next release:

```bash
rm -rf dist build
python3 -m pytest -q
python3 -m ruff check capfence tests examples
python3 -m mypy capfence
python3 -m build
python3 -m twine check dist/*
python3 -m mkdocs build --strict
```

If `mkdocs` is not installed locally, install docs dependencies first:

```bash
python3 -m pip install --require-hashes -r requirements-docs.txt
```
