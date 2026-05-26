from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

HERE = Path(__file__).resolve().parent


def main() -> None:
    from capfence import ActionEvent, ActionRuntime

    request = json.loads((HERE / "agent_request.json").read_text())
    runtime = ActionRuntime.from_policy(HERE / "policy.yaml")
    payload = request["payload"]

    event = ActionEvent.create(
        actor=request["actor"],
        action=request["action"],
        resource="shell",
        environment=request["environment"],
        risk="critical",
        capability=request["tool"],
        payload=payload,
    )
    verdict = runtime.execute(event)
    reason = "destructive_or_secret_exfiltration_risk" if not verdict.authorized else verdict.reason
    audit = {
        "audit_id": "aud_shell_001",
        "actor": request["actor"],
        "tool": request["tool"],
        "action": request["action"],
        "resource": request["resource"],
        "environment": request["environment"],
        "decision": verdict.decision,
        "reason": reason,
        "tool_invoked": verdict.authorized,
        "payload": payload,
    }
    (HERE / "audit_sample.jsonl").write_text(json.dumps(audit, separators=(",", ":")) + "\n")

    print("CapFence production shell boundary demo")
    print()
    print("Agent requested:")
    print(f"  tool: {request['tool']}")
    print(f"  environment: {request['environment']}")
    print(f"  command: {payload['command']}")
    print()
    print("CapFence decision:")
    print(f"  decision: {verdict.decision.upper()}")
    print(f"  reason: {reason}")
    print(f"  tool_invoked: {str(verdict.authorized).lower()}")
    print()
    print("Audit:")
    print("  written: audit_sample.jsonl")
    print("  replay: capfence replay audit_sample.jsonl --policy policy.yaml")


if __name__ == "__main__":
    main()
