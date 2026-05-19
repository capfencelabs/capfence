#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$repo_root"

export PYTHONPATH="$repo_root"

python_cmd="$repo_root/.venv/bin/python"
if [ ! -x "$python_cmd" ]; then
  python_cmd="python"
  if ! command -v "$python_cmd" >/dev/null 2>&1; then
    python_cmd="python3"
  fi
fi

printf "\n[DEMO] Running CapFence demo from repo root\n"
printf "[DEMO] Deterministic runtime authorization for agent tool calls, enforced before execution.\n"

printf "\n[STEP] Scan demo project for ungated tools\n"
"$python_cmd" -m capfence.cli check "capfence-demo/src"

printf "\n[STEP] Generate machine-readable scanner output\n"
"$python_cmd" -m capfence.cli check "capfence-demo/src" --report-json >/tmp/capfence-demo-scan.json
printf "[SCAN] JSON report written to /tmp/capfence-demo-scan.json\n"

printf "\n[STEP] Run live runtime decisions (block + allow)\n"
"$python_cmd" - <<'PY'
from capfence import ActionEvent, ActionRuntime, CapabilitySystem, ApprovalEngine, ImmutableAuditTrail

audit_path = "capfence-demo/audit.db"
policy_path = "policies/production_shell_policy.yaml"

caps = CapabilitySystem()
caps.load_policy(policy_path)
runtime = ActionRuntime(
    capability_system=caps,
    approval_engine=ApprovalEngine(db_path="capfence-demo/approvals.db"),
    audit_trail=ImmutableAuditTrail(db_path=audit_path),
)
event = ActionEvent.create(
    actor="demo-agent",
    action="execute",
    resource="shell",
    environment="production",
    risk="high",
    payload={"command": "rm -rf /tmp/cache"},
)
verdict = runtime.execute(event)
print(f"[RUNTIME] blocked authorized={verdict.authorized} decision={verdict.decision} reason={verdict.reason}")

event = ActionEvent.create(
    actor="demo-agent",
    action="execute",
    resource="shell",
    environment="production",
    risk="low",
    payload={"command": "ls -la /tmp"},
)
verdict = runtime.execute(event)
print(f"[RUNTIME] allowed authorized={verdict.authorized} decision={verdict.decision} reason={verdict.reason}")
PY

printf "\n[STEP] Grant expiring capability pre-authorization via CLI\n"
"$python_cmd" -m capfence.cli grant --actor demo-agent --capability shell.execute.production --duration 300 --db-path capfence-demo/approvals.db

printf "\n[STEP] Simulate trace replay\n"
cat > /tmp/capfence-replay-trace.json <<'JSON'
[
  {"capfence_replay_version": "1.0", "checksum": "ignore"},
  {
    "actor": "demo-agent",
    "action": "execute",
    "resource": "shell",
    "environment": "production",
    "risk": "low",
    "payload": {"command": "ls -la /tmp"},
    "decision": "pass"
  }
]
JSON
"$python_cmd" -m capfence.cli replay "/tmp/capfence-replay-trace.json" --policy "policies/production_shell_policy.yaml"

printf "\n[STEP] Verify audit log hash chain\n"
"$python_cmd" -m capfence.cli verify --audit-log "capfence-demo/audit.db"

printf "\n[STEP] Validate a sample policy file\n"
"$python_cmd" -m capfence.cli check-policy "policies/production_shell_policy.yaml"

printf "\n[DEMO] Done.\n"
