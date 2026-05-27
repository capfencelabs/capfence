# CapFence CLI

This document tracks the current public CLI surface.

## `capfence check`

Scans Python code for agent tool classes/functions and reports whether they are
wrapped by CapFence.

```bash
capfence check PATH [--framework TEXT] [--strict] [--fail-on-ungated] [--report-json]
```

Supported framework filters:

- `langchain`
- `crewai`
- `autogen`
- `pydanticai`
- `llamaindex`

## `capfence check-policy`

Validates a CapFence YAML policy.

```bash
capfence check-policy policies/packs/filesystem/policy.yaml
```

## `capfence policy test`

Runs policy fixture cases and exits non-zero on failure.

```bash
capfence policy test tests/fixtures/policy-packs/starter_pack_cases.yaml
```

## `capfence policy explain`

Explains how a policy evaluates one event fixture.

```bash
capfence policy explain POLICY_FILE EVENT_FILE
capfence policy explain POLICY_FILE EVENT_FILE --json
```

## `capfence policy diff`

Compares two policies against the same fixture corpus and highlights verdict
transitions, including newly allowed side effects.

```bash
capfence policy diff BEFORE_POLICY AFTER_POLICY FIXTURE_FILE
```

## `capfence replay`

Replays an audit trace or simulates a custom policy over a trace.

```bash
capfence replay TRACE_FILE
capfence replay TRACE_FILE --policy POLICY_FILE
```

## `capfence verify`

Verifies the SQLite audit log hash chain. For rows with stored signatures, it
also verifies those signatures and fails closed if the audit public key is
missing or the signature is invalid.

```bash
capfence verify --audit-log audit.db
```

## Approval Commands

```bash
capfence pending-approvals --db-path capfence_approvals.db
capfence approve REQUEST_ID --db-path capfence_approvals.db --user alice
capfence reject REQUEST_ID --db-path capfence_approvals.db --user alice
capfence grant --actor agent --capability filesystem.read --duration 3600
```

## Audit Inspection

```bash
capfence logs --audit-log audit.db --limit 50
capfence logs --audit-log audit.db --json
capfence trace TRACE_ID --audit-log audit.db
```

## `capfence eu-ai-act`

Generates an HTML technical evidence report from static scan results and,
optionally, an audit log.

```bash
capfence eu-ai-act SRC_PATH --output eu-ai-act-report.html
capfence eu-ai-act SRC_PATH --audit-log audit.db --output eu-ai-act-report.html
```

The report is technical evidence, not a legal compliance determination.

## `capfence taxonomy list`

Lists bundled taxonomy categories and mapped capabilities.

```bash
capfence taxonomy list
capfence taxonomy list --domain financial --format json
```

## Removed Internal Commands

Older internal planning docs referenced `capfence assess`, `capfence simulate`,
and `capfence owasp`. Those commands are not part of the current public CLI.
Use `check`, `replay`, `policy`, and `eu-ai-act` workflows instead.
