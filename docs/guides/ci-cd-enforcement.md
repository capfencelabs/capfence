# CI/CD Enforcement

CapFence's static scanner can block CI/CD pipelines when ungated AI agent tools are detected. This prevents unenforced tools from reaching production.

## What the scanner checks

`capfence check` parses Python files with the AST module and identifies:

- LangChain `BaseTool` subclasses not wrapped with `CapFenceTool`
- CrewAI `BaseTool` subclasses not wrapped
- OpenAI Agents SDK function tools not gated
- MCP tool definitions without a gateway

Cross-file detection is supported: a tool defined in `tools.py` and wrapped in `agent.py` is correctly detected as gated.

## GitHub Actions

```yaml
# .github/workflows/capfence.yml
name: CapFence Gate Check

on: [push, pull_request]

jobs:
  gate-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install CapFence
        run: pip install capfence

      - name: Check for ungated tools
        run: capfence check ./src --fail-on-ungated

      - name: Generate HTML report (on failure)
        if: failure()
        run: capfence check ./src -o report.html

      - name: Upload report
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: capfence-report
          path: report.html
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No ungated high-risk tools found |
| `1` | Ungated high-risk tools found (`--fail-on-ungated` set) |
| `2` | Invalid arguments or path not found |

## Framework-specific checks

```bash
# Check only LangChain tools
capfence check ./src --framework langchain

# Check only CrewAI tools
capfence check ./src --framework crewai

# Check only OpenAI Agents SDK tools
capfence check ./src --framework openai_agents
```

## Machine-readable scan report

For CI systems that need structured output:

```bash
capfence check ./src --report-json
```

The JSON output includes discovered tools, framework, category, risk delta, source location, and gated status.

## Pre-commit hook

Add a pre-commit check so developers catch issues before pushing:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: capfence-check
        name: CapFence gate check
        entry: capfence check --fail-on-ungated
        language: system
        types: [python]
```

## Related guides

- [Observe mode rollout](observe-mode-rollout.md)
- [Air-gapped deployments](air-gapped-deployments.md)
- [CLI reference](../reference/cli.md)
