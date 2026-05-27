# Air-Gapped Deployments

CapFence runs entirely locally. It makes no outbound network calls during operation. All enforcement, audit logging, and approval workflows function without internet access.

## What runs locally

| Component | Storage |
|---|---|
| Runtime gate | In-process, no network |
| Policy evaluation | In-process, reads local YAML |
| Audit log | Local SQLite file (`./audit.db`) |
| Approval queue | Local SQLite file |
| CLI commands | Local process |

## Installation in air-gapped environments

Download the package and its dependencies on a networked machine, transfer to the air-gapped environment, and install from the local archive:

```bash
# On networked machine
pip download capfence -d ./packages

# Transfer ./packages to air-gapped machine
# On air-gapped machine
pip install --no-index --find-links ./packages capfence
```

## Offline verification

Audit log verification runs locally:

```bash
capfence verify --audit-log ./audit.db
```

No external service is contacted.

## Policy files

Policies are plain YAML files. Manage them as code in your version control system and deploy them alongside your application. No CapFence service needs to be reachable.

## Approval workflows in air-gapped environments

The approval queue is stored in local SQLite. Reviewers run `capfence pending-approvals` and `capfence approve <id>` on the same machine (or a machine with access to the shared SQLite file).

For multi-machine environments, point all nodes at a shared network path for the audit database:

```python
from capfence.core.audit import AuditLogger
from capfence import ActionRuntime

runtime = ActionRuntime.from_policy("/etc/capfence/policy.yaml")
runtime.audit_trail = AuditLogger(db_path="/shared/nfs/capfence/audit.db")
```

## Log export for offline analysis

View audit logs as JSON for analysis on a separate system:

```bash
capfence logs --audit-log audit.db --json > audit_export.json
```

Analysis can be run on the exported file on any machine with CapFence installed.

## What is not available offline

- PyPI package updates (expected — install from local archive)
- Any future cloud dashboard or telemetry features (not part of the open-source package)

## Related guides

- [CI/CD enforcement](ci-cd-enforcement.md)
- [Replay an incident](replay-an-incident.md)
