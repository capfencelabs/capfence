from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

HERE = Path(__file__).resolve().parent


def main() -> None:
    from capfence import ActionEvent, ActionRuntime
    from queries import DESTRUCTIVE_QUERY

    runtime = ActionRuntime.from_policy(HERE / "policy.yaml")
    payload = {"query": DESTRUCTIVE_QUERY}
    event = ActionEvent.create(
        actor="analytics-agent",
        action="execute",
        resource="db:customers",
        environment="production",
        risk="critical",
        capability="database.query",
        payload=payload,
    )
    verdict = runtime.execute(event)
    reason = "destructive_schema_change_in_production"
    audit = {
        "audit_id": "aud_db_001",
        "actor": "analytics-agent",
        "tool": "database.query",
        "action": "execute",
        "resource": "db:customers",
        "environment": "production",
        "decision": verdict.decision,
        "reason": reason,
        "tool_invoked": verdict.authorized,
        "payload": payload,
    }
    (HERE / "audit_sample.jsonl").write_text(json.dumps(audit, separators=(",", ":")) + "\n")
    print("requested: database.query")
    print(f"query: {DESTRUCTIVE_QUERY}")
    print(f"decision: {verdict.decision.upper()}")
    print(f"reason: {reason}")
    print(f"tool_invoked: {str(verdict.authorized).lower()}")


if __name__ == "__main__":
    main()
