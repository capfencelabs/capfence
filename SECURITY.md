# CapFence Security Policy

CapFence is a runtime authorization layer for AI agent side effects. It is designed to work in local, offline, and tightly controlled environments, but deployment assurance depends on how operators gate credentials, tools, policy files, and audit storage.

## Enterprise Trust Signals and Security Boundaries

- **Offline-First & Air-Gapped**: CapFence has zero external network dependencies. It does not phone home, it does not send telemetry by default, and it does not rely on cloud-hosted LLMs for policy evaluation.
- **Deterministic Enforcement**: Risk scoring relies on regex boundary matching and AST parsing. Unlike LLM-based guardrails, execution decisions are reproducible and predictable.
- **Hash-Chained Audit Logging**: Evaluations are recorded in a local SQLite database. The cryptographic hash chain is tamper-evident for local edits, but operators should export evidence off-host for stronger assurance.
- **Fail-Closed Execution**: Unknown capabilities, malformed policies, and unavailable approval paths resolve to deny or require approval rather than silent allow.
- **Adapter Boundary**: CapFence protects the tool path that is actually routed through a CapFence adapter or gateway. Direct credential use outside that path is out of scope.

## Supported Versions

We currently support the following versions for security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
| < 0.8.0 | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in CapFence, please do NOT open a public issue.

Instead, please send an email to **[anshuman1405@outlook.com](mailto:anshuman1405@outlook.com)**.

We will acknowledge receipt of your vulnerability report within 48 hours and provide a timeline for remediation. We prioritize vulnerabilities that allow:
- Bypassing the runtime gate.
- Tampering with the hash-chained audit log.
- Causing a denial of service in the evaluation pipeline.

## Threat Model

Please see our [Security Architecture](docs/security/security-architecture.md) and [Threat Model](docs/architecture/threat-model.md) for details on the enforcement model, bypass cases, host assumptions, and failure behavior.
