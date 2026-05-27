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
| `-f, --framework TEXT` | Filter by framework, such as `langchain`, `crewai`, `autogen`, `pydanticai`, or `llamaindex`. |
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

Verify the integrity of a hash-chained audit log. If signed rows are present,
the command also verifies stored signatures and fails closed when the local
audit public key is unavailable or invalid.

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

## `capfence eu-ai-act`

Generate an EU AI Act technical evidence report from static scan results and,
optionally, an audit log.

```bash
capfence eu-ai-act ./src --output eu-ai-act.html
capfence eu-ai-act ./src --audit-log audit.db --output eu-ai-act.html
```

Options:

| Flag | Description |
|---|---|
| `SRC_PATH` | Codebase path to assess. Required. |
| `-o, --output PATH` | Write HTML evidence report. |
| `-a, --audit-log PATH` | Optional SQLite audit log for Article 12 evidence. |

---

## Removed Internal Commands

Older internal planning docs referenced `capfence assess`, `capfence simulate`,
`capfence owasp`, and `capfence tune`. Those commands are not part of the
current public CLI.
