from __future__ import annotations

import pytest
from click.testing import CliRunner
from pathlib import Path

from capfence.cli import main
from capfence import ActionRuntime, ActionEvent
from capfence.core.policy import PolicyLoader
from capfence.errors import PolicyLoadError


def test_policy_conditions_contains_amount_lte_and_path_prefix(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
deny:
  - capability: shell.execute
    contains: "rm -rf"
  - capability: filesystem.write
    path_prefix: "/etc"

require_approval:
  - capability: payments.transfer
    amount_gt: 1000

allow:
  - capability: shell.execute
  - capability: filesystem.write
    path_prefix: "/tmp"
  - capability: payments.transfer
    amount_lte: 1000
""",
        encoding="utf-8",
    )

    runtime = ActionRuntime.from_policy(str(policy_path))

    # 1. Shell blocked
    event_blocked_shell = ActionEvent.create(
        actor="agent",
        action="execute",
        resource="shell",
        environment="production",
        payload={"command": "rm -rf /tmp/cache"},
    )
    verdict_blocked_shell = runtime.execute(event_blocked_shell)
    assert verdict_blocked_shell.authorized is False
    assert verdict_blocked_shell.decision == "deny"
    assert verdict_blocked_shell.reason == "policy_deny"

    # 2. Shell allowed
    event_allowed_shell = ActionEvent.create(
        actor="agent",
        action="execute",
        resource="shell",
        environment="production",
        payload={"command": "ls /tmp"},
    )
    verdict_allowed_shell = runtime.execute(event_allowed_shell)
    assert verdict_allowed_shell.authorized is True
    assert verdict_allowed_shell.decision == "allow"
    assert verdict_allowed_shell.reason == "policy_allow"

    # 3. Path prefix blocked
    event_blocked_path = ActionEvent.create(
        actor="agent",
        action="write",
        resource="filesystem",
        environment="production",
        payload={"path": "/etc/hosts", "content": "x"},
    )
    verdict_blocked_path = runtime.execute(event_blocked_path)
    assert verdict_blocked_path.authorized is False
    assert verdict_blocked_path.decision == "deny"
    assert verdict_blocked_path.reason == "policy_deny"

    # 4. Amount allowed
    event_allowed_amount = ActionEvent.create(
        actor="agent",
        action="transfer",
        resource="payments",
        environment="production",
        payload={"amount": 500},
    )
    verdict_allowed_amount = runtime.execute(event_allowed_amount)
    assert verdict_allowed_amount.authorized is True
    assert verdict_allowed_amount.decision == "allow"
    assert verdict_allowed_amount.reason == "policy_allow"

    # 5. Amount requires approval
    event_approval_amount = ActionEvent.create(
        actor="agent",
        action="transfer",
        resource="payments",
        environment="production",
        payload={"amount": 1500},
    )
    verdict_approval_amount = runtime.execute(event_approval_amount)
    assert verdict_approval_amount.authorized is False
    assert verdict_approval_amount.decision.startswith("require_approval")


def test_policy_default_deny_when_no_rule_matches(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
allow:
  - capability: filesystem.read
""",
        encoding="utf-8",
    )

    runtime = ActionRuntime.from_policy(str(policy_path))
    event = ActionEvent.create(
        actor="agent",
        action="write",
        resource="database",
        environment="production",
        payload={"query": "select 1"},
    )
    verdict = runtime.execute(event)

    assert verdict.authorized is False
    assert verdict.decision == "deny"
    assert verdict.reason == "policy_default_deny"


def test_policy_error_fails_closed(tmp_path):
    policy_path = tmp_path / "bad.yaml"
    policy_path.write_text(
        """
allow:
  - description: missing capability
""",
        encoding="utf-8",
    )

    with pytest.raises(PolicyLoadError):
        ActionRuntime.from_policy(str(policy_path))


def test_policy_caller_depth_condition(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
deny:
  - capability: agent.delegate
    caller_depth_gt: 2
allow:
  - capability: agent.delegate
""",
        encoding="utf-8",
    )

    runtime = ActionRuntime.from_policy(str(policy_path))
    event = ActionEvent.create(
        actor="agent",
        action="delegate",
        resource="agent",
        environment="production",
        payload={"target": "subagent"},
        caller_depth=3
    )
    verdict = runtime.execute(event)

    assert verdict.authorized is False
    assert verdict.decision == "deny"
    assert verdict.reason == "policy_deny"


def test_policy_loader_rejects_unknown_condition(tmp_path):
    policy_path = tmp_path / "bad.yaml"
    policy_path.write_text(
        """
allow:
  - capability: shell.execute
    made_up_condition: true
""",
        encoding="utf-8",
    )

    try:
        PolicyLoader().load(policy_path)
    except Exception as exc:
        assert type(exc).__name__ == "PolicyLoadError"
        assert "made_up_condition" in str(exc)
    else:
        raise AssertionError("PolicyLoader accepted an unknown condition")


def test_check_policy_cli(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
allow:
  - capability: shell.execute
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["check-policy", str(policy_path)])

    assert result.exit_code == 0
    assert "[POLICY] VALID" in result.output


def test_legacy_rules_policy_schema(tmp_path):
    policy_path = tmp_path / "legacy.yaml"
    policy_path.write_text(
        """
version: "1.0"
policy_name: legacy_shell
description: Legacy starter policy shape
enforcement_mode: block
rules:
  - id: destructive
    description: Block destructive shell commands
    match_keywords:
      - "rm -rf"
    threshold: 0.1
    action: block
  - id: read_only
    description: Allow simple list commands
    match_regex:
      - "^ls"
    action: allow
""",
        encoding="utf-8",
    )

    runtime = ActionRuntime.from_policy(str(policy_path))
    
    event_blocked = ActionEvent.create(
        actor="agent",
        action="execute",
        resource="shell",
        environment="production",
        payload={"command": "rm -rf /tmp/cache"},
    )
    verdict_blocked = runtime.execute(event_blocked)
    
    event_allowed = ActionEvent.create(
        actor="agent",
        action="execute",
        resource="shell",
        environment="production",
        payload={"command": "ls /tmp"},
    )
    verdict_allowed = runtime.execute(event_allowed)

    assert verdict_blocked.authorized is False
    assert verdict_blocked.decision == "deny"
    assert verdict_blocked.reason == "policy_deny"
    assert verdict_allowed.authorized is True
    assert verdict_allowed.decision == "allow"
    assert verdict_allowed.reason == "policy_allow"
