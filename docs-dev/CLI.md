# CapFence CLI Reference

## Installation

```bash
pip install capfence
```

All commands are available via the `capfence` entry point.

---

## `capfence check`

Statically scan a Python codebase for ungated AI agent tools.

### Synopsis

```
capfence check [OPTIONS] [PATH]
```

### Description

Parses Python files with the AST module, identifies tool classes and functions (LangChain `BaseTool`, CrewAI `BaseTool`, or function-based tools), and flags any that are **not** wrapped with a CapFence adapter. Supports cross-file wrapper detection — a tool defined in `tools.py` and wrapped in `agent.py` is correctly detected as gated.

### Options

| Flag | Description |
|---|---|
| `PATH` | Directory or file to scan. Defaults to current directory `.` |
| `-o, --output PATH` | Write HTML report to file |
| `--framework TEXT` | Filter findings by framework (`langchain`, `crewai`, `openai_agents`, `mcp`) |
| `--exclude-dir TEXT` | Exclude directories (default: `venv`, `.venv`, `__pycache__`, `.git`) |
| `--fail-on-ungated` | Exit with non-zero code if high-risk ungated tools are found |

### Examples

```bash
# Scan current directory
capfence check

# Scan specific path with HTML report
capfence check ./src -o report.html

# CI/CD — block deploy if ungated tools exist
capfence check ./src --fail-on-ungated

# Filter to LangChain tools only
capfence check ./src --framework langchain
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Scan completed, no ungated high-risk tools (or `--fail-on-ungated` not set) |
| 1 | `--fail-on-ungated` set and ungated high-risk tools found |
| 2 | Invalid arguments or path not found |

---

## `capfence assess`

Full risk assessment with taxonomy enrichment and compliance mapping.

### Synopsis

```
capfence assess [OPTIONS] PATH
```

### Description

Runs the static scanner, enriches findings with taxonomy data (risk keywords, thresholds, compliance frameworks), and generates a professional HTML report with executive summary, risk breakdown, and remediation plan.

### Options

| Flag | Description |
|---|---|
| `PATH` | Directory to assess |
| `-o, --output PATH` | Output HTML report path |
| `-t, --taxonomy TEXT` | Taxonomy to use (`general`, `financial`, `legal`, `financial_plaid`) |
| `--compliance` | Include SOX/PCI-DSS/GDPR compliance mappings |

### Examples

```bash
# Basic assessment
capfence assess ./src

# Financial taxonomy with compliance mappings
capfence assess ./src --taxonomy financial --compliance -o assessment.html

# Plaid-specific fintech assessment
capfence assess ./src --taxonomy financial_plaid
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Assessment completed successfully |
| 1 | Assessment failed (invalid path, parse errors, or internal error) |

---

## `capfence simulate`

Replay agent execution traces through the CapFence gate.

### Synopsis

```
capfence simulate [OPTIONS]
```

### Description

Reads a JSONL trace file (one JSON object per line, each representing a tool call) and replays each call through the gate. Compares static vs. adaptive scoring side-by-side. Useful for regression testing and detecting behavioral drift.

### Options

| Flag | Description |
|---|---|
| `--trace-file PATH` | JSONL trace file to replay (required) |
| `-t, --taxonomy TEXT` | Taxonomy to use |
| `--compare` | Compare static vs. adaptive scoring results |
| `-o, --output PATH` | Write comparison report to file |

### Examples

```bash
# Replay traces with static scoring
capfence simulate --trace-file traces.jsonl --taxonomy general

# Compare static vs. adaptive
capfence simulate --trace-file traces.jsonl --taxonomy general --compare

# Save comparison report
capfence simulate --trace-file traces.jsonl --compare -o comparison.html
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Simulation completed |
| 1 | Invalid trace file or internal error |

---

## `capfence build-taxonomy`

Interactively build a custom risk taxonomy.

### Synopsis

```
capfence build-taxonomy [OPTIONS]
```

### Description

Prompts for industry, payment methods, and compliance frameworks, then generates a tailored JSON taxonomy file. The generated taxonomy can be loaded via `--taxonomy` in other commands.

### Options

| Flag | Description |
|---|---|
| `-o, --output PATH` | Output JSON file path (default: `custom-taxonomy.json`) |

### Examples

```bash
# Interactive build
capfence build-taxonomy

# Save to specific file
capfence build-taxonomy -o my-taxonomy.json
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Taxonomy built successfully |
| 1 | Build cancelled or error |

---

## `capfence verify`

Verify the integrity of a hash-chained audit log.

### Synopsis

```
capfence verify [OPTIONS] AUDIT_LOG
```

### Description

Reads an SQLite audit log database and verifies the SHA-256 hash chain linking all entries. If Ed25519 signing is enabled, also verifies signatures. Reports any tampered, missing, or out-of-order entries.

### Arguments

| Argument | Description |
|---|---|
| `AUDIT_LOG` | Path to SQLite audit database (default: `audit.db`) |

### Examples

```bash
# Verify default audit.db
capfence verify

# Verify specific database
capfence verify /var/log/capfence.db
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Chain valid, no tampering detected |
| 1 | Chain invalid — tampering or corruption detected |
| 2 | Database not found or unreadable |

---

## `capfence owasp`

Generate an OWASP Agentic Top 10 coverage matrix.

### Synopsis

```
capfence owasp [OPTIONS]
```

### Description

Maps CapFence's controls to the OWASP Agentic AI Top 10 risks. Generates an HTML report showing which risks are fully covered, partially covered, or not applicable. Useful for security questionnaires and compliance documentation.

### Options

| Flag | Description |
|---|---|
| `-o, --output PATH` | Output HTML report path (default: `capfence-owasp-report.html`) |

### Examples

```bash
# Generate coverage matrix
capfence owasp

# Save to specific file
capfence owasp -o owasp-coverage.html
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Report generated successfully |
| 1 | Report generation failed |

---

## `capfence eu-ai-act`

Generate an EU AI Act Annex IV evidence pack.

### Synopsis

```
capfence eu-ai-act [OPTIONS] PATH
```

### Description

Scans the codebase, assesses risk posture, and generates a structured evidence pack for EU AI Act Annex IV compliance. Produces both JSON (machine-readable) and HTML (human-readable) outputs covering risk management, cybersecurity, data governance, and technical documentation.

### Options

| Flag | Description |
|---|---|
| `PATH` | Directory to scan (default: `.`) |
| `-t, --taxonomy TEXT` | Taxonomy to use for risk assessment |
| `-o, --output PATH` | Output HTML report path |
| `--json-output PATH` | Output JSON evidence pack path |
| `--system-name TEXT` | System name for the evidence pack (default: `CapFence System`) |

### Examples

```bash
# Generate evidence pack for current directory
capfence eu-ai-act . --taxonomy general --system-name "MyAgent"

# Generate both HTML and JSON
capfence eu-ai-act ./src --taxonomy financial --system-name "FintechAgent" -o evidence.html --json-output evidence.json
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Evidence pack generated successfully |
| 1 | Generation failed (invalid path, missing taxonomy, or internal error) |

---

## `capfence grant`

Grant temporary or session pre-authorizations to an autonomous agent.

### Synopsis

```
capfence grant [OPTIONS]
```

### Description

Provisions temporary time-bound or session-bound capability pre-authorizations to an actor, saving the grant state to the SQLite database (defaults to approvals.db). This enables operations webhooks, Slack bots, or automation pipelines to grant temporary privileges to agents.

### Options

| Flag | Description |
|---|---|
| `--actor TEXT` | Target actor identifier (required) |
| `--capability TEXT` | Scoped capability string in resource.action.scope format (required) |
| `--environment TEXT` | Target environment target (e.g. production, development, or wildcard '*') (default: '*') |
| `--duration FLOAT` | Duration in seconds for a temporary grant (default: 3600.0) |
| `--session TEXT` | Session ID for a session-locked grant |
| `--by TEXT` | Identifier of the operational authority issuing the grant (default: ops_admin) |
| `--approvals-db PATH` | Path to SQLite approvals database (default: approvals.db) |

### Examples

```bash
# Grant a 1-hour temporary authorization for ops-agent to delete production workspaces
capfence grant --actor ops-agent --capability filesystem.delete.workspace --duration 3600 --environment production

# Grant a session-locked push permission to hotfix-agent
capfence grant --actor hotfix-agent --capability github.push.main --session session-7789 --by github_actions
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Pre-authorization grant created and persisted successfully |
| 1 | Invalid parameters or db write error |

---

## Global Options

All commands support:

| Flag | Description |
|---|---|
| `--version` | Show version and exit |
| `--help` | Show help message and exit |

---

## Environment Variables

| Variable | Affected Command | Description |
|---|---|---|
| `CAPFENCE_TELEMETRY` | All | Set to `1` to enable opt-in telemetry (hashed metadata only) |
| `CAPFENCE_API_KEY` | `telemetry` | API key for telemetry endpoint (if not using default) |
