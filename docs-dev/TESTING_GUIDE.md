# Testing CapFence

This guide describes the current local validation flow for the CapFence Python
package. It is intended for contributors working from the repository checkout.

## Setup

```bash
python3 -m pip install --upgrade pip
python3 -m pip install --require-hashes -r requirements-dev.txt
python3 -m pip install -e . --no-deps
```

Install docs tooling only when building the documentation site:

```bash
python3 -m pip install --require-hashes -r requirements-docs.txt
```

Install build tooling only when checking release artifacts:

```bash
python3 -m pip install --require-hashes -r requirements-build.txt
```

## Core Validation

Run these before opening a PR:

```bash
python3 -m pytest -q
python3 -m ruff check capfence tests examples
python3 -m mypy capfence
```

The exact test count changes as coverage grows, so treat the command exit status
as authoritative rather than a fixed number in this document.

## Release Dry Run

Use this before tagging or publishing:

```bash
rm -rf dist build
python3 -m pytest -q
python3 -m ruff check capfence tests examples
python3 -m mypy capfence
python3 -m build
python3 -m twine check dist/*
python3 -m mkdocs build --strict
```

## Focused Test Commands

Policy engine and policy-pack fixtures:

```bash
python3 -m pytest tests/test_policy_engine.py tests/test_policy_pack_cli.py -q
capfence policy test tests/fixtures/policy-packs/starter_pack_cases.yaml
```

Framework adapters:

```bash
python3 -m pytest \
  tests/test_framework_langchain.py \
  tests/test_framework_langgraph.py \
  tests/test_framework_openai_agents.py \
  tests/test_framework_additional_adapters.py \
  tests/test_mcp.py \
  -q
```

Audit chain and signing:

```bash
python3 -m pytest tests/test_core_chain.py tests/test_core_keys.py -q
```

CLI reports:

```bash
python3 -m pytest tests/test_cli_taxonomy.py tests/test_cli_eu_ai_act.py -q
```

## CLI Smoke Tests

```bash
capfence --version
capfence check examples --report-json
capfence check-policy policies/packs/filesystem/policy.yaml
capfence policy explain policies/packs/filesystem/policy.yaml tests/fixtures/policy-packs/starter_pack_cases.yaml
capfence taxonomy list --format json
```

## Current Public Adapter Surface

The package ships importable wrappers for:

- `capfence.framework.langchain.CapFenceTool`
- `capfence.framework.langgraph.CapFenceToolNode`
- `capfence.framework.openai_agents.CapFenceOpenAITool`
- `capfence.framework.crewai.CapFenceCrewAITool`
- `capfence.framework.autogen.CapFenceAutoGenTool`
- `capfence.framework.llamaindex.CapFenceLlamaIndexTool`
- `capfence.framework.pydanticai.CapFencePydanticTool`
- `capfence.mcp.gateway.MCPGatewayServer`
- `capfence.mcp.adapter.CapFenceMCPSession`

Adapter wrappers are duck-typed where possible so CapFence can be imported
without forcing every framework dependency into the base installation.

## Audit Signing Notes

`AuditLogger.verify()` always verifies the SHA-256 hash chain. If a row contains
a signature, verification also checks that signature and fails closed when the
local audit public key is unavailable or invalid.

Install the crypto extra for Ed25519 signatures:

```bash
python3 -m pip install "capfence[crypto]"
```

Without the extra, CapFence may use a compatibility fallback for local testing.
That fallback is not Ed25519-equivalent and should not be described as
production-grade signing.
