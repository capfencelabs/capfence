from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

HERE = Path(__file__).resolve().parent


def main() -> None:
    from capfence import ActionEvent, ActionRuntime
    from mcp_server_demo import read_file

    path = "~/.ssh/id_rsa"
    runtime = ActionRuntime.from_policy(HERE / "policy.yaml")
    event = ActionEvent.create(
        actor="ide-agent",
        action="read",
        resource="mcp.filesystem",
        environment="development",
        risk="critical",
        capability="mcp.filesystem.read",
        payload={"path": path},
    )
    verdict = runtime.execute(event)
    upstream_invoked = False
    if verdict.authorized:
        read_file(path)
        upstream_invoked = True

    reason = "path_outside_workspace_or_secret_file"
    audit = {
        "audit_id": "aud_mcp_fs_001",
        "actor": "ide-agent",
        "tool": "mcp.filesystem.read",
        "action": "read",
        "resource": path,
        "environment": "development",
        "decision": verdict.decision,
        "reason": reason,
        "upstream_mcp_invoked": upstream_invoked,
        "payload": {"path": path},
    }
    (HERE / "audit_sample.jsonl").write_text(json.dumps(audit, separators=(",", ":")) + "\n")
    print("requested: mcp.filesystem.read")
    print(f"path: {path}")
    print(f"decision: {verdict.decision.upper()}")
    print(f"reason: {reason}")
    print(f"upstream_mcp_invoked: {str(upstream_invoked).lower()}")


if __name__ == "__main__":
    main()
