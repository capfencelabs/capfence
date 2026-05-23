from __future__ import annotations

from click.testing import CliRunner

from capfence.cli import main
from capfence.core.policy_backends import OPAPolicyBackend
from capfence.core.policy_testing import normalize_event, run_policy_fixture_file


def test_starter_pack_fixture_suite_passes() -> None:
    suite = run_policy_fixture_file("tests/fixtures/policy-packs/starter_pack_cases.yaml")

    assert suite.passed is True
    assert suite.total >= 20


def test_policy_explain_outputs_json() -> None:
    result = CliRunner().invoke(
        main,
        [
            "policy",
            "explain",
            "policies/packs/shell/baseline.yaml",
            "tests/fixtures/policy-packs/starter_pack_cases.yaml",
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert '"final_verdict": "deny"' in result.output
    assert '"capability": "shell.exec"' in result.output


def test_policy_event_normalization_accepts_action_event_shape() -> None:
    capability, context, payload = normalize_event(
        {
            "actor": "ops-agent",
            "action": "exec",
            "resource": "shell",
            "environment": "production",
            "payload": {"command": "git status"},
        }
    )

    assert capability == "shell.exec.*"
    assert context["actor"] == "ops-agent"
    assert context["action"] == "exec"
    assert payload == {"command": "git status"}


def test_opa_backend_fails_closed_when_unavailable() -> None:
    backend = OPAPolicyBackend("http://127.0.0.1:1/v1/data/capfence/authz", timeout_seconds=0.01)

    decision = backend.evaluate(
        "shell.exec",
        {"environment": "production"},
        {"command": "sudo systemctl restart nginx"},
    )

    assert decision.verdict == "deny"
    assert decision.reason.startswith("opa_unavailable_fail_closed")
