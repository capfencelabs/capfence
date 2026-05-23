# CLI Reference

All commands are available through the `capfence` entry point after installation.

```bash
pip install capfence
capfence --version
```

---

## `capfence check`

Scan Python files for ungated AI agent tools.

```bash
capfence check [OPTIONS] PATH
```

Options:

| Flag | Description |
|---|---|
| `PATH` | File or directory to scan. Defaults to `.` |
| `-f, --framework TEXT` | Filter by framework, such as `langchain`, `crewai`, or `autogen`. |
| `--fail-on-ungated` | Exit non-zero if high-risk ungated tools are found. |
| `--strict` | Exit non-zero if any ungated tools are found. |
| `--report-json` | Print findings as JSON. |

Examples:

```bash
capfence check ./src
capfence check ./src --fail-on-ungated
capfence check ./src --framework langchain --report-json
```

---

## `capfence check-policy`

Validate a CapFence YAML policy file.

```bash
capfence check-policy POLICY_FILE
```

---

## `capfence policy test`

Run named policy fixture suites with expected `allow`, `deny`, or `require_approval` verdicts.

```bash
capfence policy test tests/fixtures/policy-packs/starter_pack_cases.yaml
capfence policy test tests/fixtures/policy-packs/starter_pack_cases.yaml --json
```

---

## `capfence policy explain`

Explain the matched policy section, rule, predicate result, and final verdict for an event fixture.

```bash
capfence policy explain policies/packs/shell/baseline.yaml event.yaml
capfence policy explain policies/packs/shell/baseline.yaml event.yaml --json
```

---

## `capfence policy diff`

Compare two policies against the same fixture corpus and group verdict transitions.

```bash
capfence policy diff policies/packs/shell/strict.yaml policies/packs/shell/permissive.yaml tests/fixtures/policy-packs/starter_pack_cases.yaml
```

The command highlights newly allowed side effects.

---

## `capfence verify`

Verify the integrity of a hash-chained audit log.

```bash
capfence verify --audit-log audit.db
```

Options:

| Flag | Description |
|---|---|
| `-a, --audit-log PATH` | SQLite audit log to verify. Required. |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Audit chain is valid. |
| `3` | Audit chain is invalid. |

---

## `capfence logs`

View structured audit events.

```bash
capfence logs [OPTIONS]
```

Options:

| Flag | Description |
|---|---|
| `-a, --audit-log PATH` | SQLite audit log. Defaults to `audit.db`. |
| `--agent TEXT` | Filter by agent ID. |
| `--limit INTEGER` | Number of events to show. Defaults to `50`. |
| `--json` | Print events as JSON. |

Examples:

```bash
capfence logs --audit-log audit.db
capfence logs --agent finance-agent --json
```

---

## `capfence trace`

Show a detailed execution trace for an audit entry hash or payload hash.

```bash
capfence trace TRACE_ID --audit-log audit.db
```

Options:

| Flag | Description |
|---|---|
| `TRACE_ID` | Entry hash or payload hash. |
| `-a, --audit-log PATH` | SQLite audit log. Defaults to `audit.db`. |

---

## `capfence replay`

Replay a JSONL trace file for deterministic output.

```bash
capfence replay trace.jsonl
capfence replay trace.jsonl --policy policies/candidate.yaml
```

Options:

| Flag | Description |
|---|---|
| `TRACE_FILE` | JSON or JSONL replay trace. |
| `-p, --policy PATH` | Candidate policy file to use during replay. |

---

## `capfence pending-approvals`

List pending approval requests.

```bash
capfence pending-approvals --db-path capfence_approvals.db
```

Options:

| Flag | Description |
|---|---|
| `-d, --db-path PATH` | Approval database. Defaults to `capfence_approvals.db`. |

---

## `capfence approve`

Approve a pending tool execution.

```bash
capfence approve REQUEST_ID --user alice@example.com
```

Options:

| Flag | Description |
|---|---|
| `REQUEST_ID` | Approval request ID. |
| `-d, --db-path PATH` | Approval database. Defaults to `capfence_approvals.db`. |
| `-u, --user TEXT` | User approving the request. Defaults to `cli_user`. |

---

## `capfence reject`

Reject a pending tool execution.

```bash
capfence reject REQUEST_ID --user alice@example.com
```

Options are the same as `approve`.

---

## `capfence owasp`

Generate an OWASP Agentic Top 10 coverage matrix.

```bash
capfence owasp --output owasp.html
```

---

## `capfence eu-ai-act`

Generate an EU AI Act Annex IV evidence pack from a codebase assessment.

```bash
capfence eu-ai-act ./src --output eu-ai-act.html --json-output eu-ai-act.json
```

Options:

| Flag | Description |
|---|---|
| `PATH` | Codebase path to assess. Required. |
| `-t, --taxonomy TEXT` | Taxonomy to use. Defaults to `general`. |
| `-o, --output PATH` | Write HTML evidence pack. |
| `--json-output PATH` | Write JSON evidence pack. |
| `--system-name TEXT` | System name for the evidence pack. |

---

## `capfence tune`

Analyze recent audit decisions and suggest threshold adjustments.

```bash
capfence tune --audit-log audit.db --window 200
```

Options:

| Flag | Description |
|---|---|
| `-a, --audit-log PATH` | SQLite audit log. Required. |
| `--agent-id TEXT` | Limit analysis to one agent. |
| `--window INTEGER` | Number of recent decisions to analyze. Defaults to `200`. |
| `--false-positive-budget FLOAT` | Acceptable false-positive rate. Defaults to `0.05`. |
