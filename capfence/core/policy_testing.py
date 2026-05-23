"""Policy fixture testing, explain, and diff helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore

from capfence.core.policy import PolicyLoader


@dataclass
class PolicyFixtureResult:
    name: str
    policy: str
    expected: str
    actual: str
    passed: bool
    reason: str
    explanation: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicySuiteResult:
    name: str
    results: list[PolicyFixtureResult]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def failures(self) -> int:
        return sum(1 for result in self.results if not result.passed)


def display_verdict(verdict: str | None) -> str:
    """Convert internal policy engine verdicts to fixture-facing verdict names."""
    if verdict in {None, "default_deny", "block"}:
        return "deny"
    return verdict


def load_fixture_file(path: str | Path) -> dict[str, Any]:
    fixture_path = Path(path)
    with open(fixture_path, "r", encoding="utf-8") as handle:
        if fixture_path.suffix == ".json":
            return json.load(handle)
        return yaml.safe_load(handle) or {}


def run_policy_fixture_file(path: str | Path) -> PolicySuiteResult:
    fixture_path = Path(path)
    data = load_fixture_file(fixture_path)
    suite_name = str(data.get("suite") or data.get("name") or fixture_path.stem)
    raw_cases = data.get("cases")
    if raw_cases is None:
        raw_cases = [data]
    if not isinstance(raw_cases, list):
        raise ValueError("Policy fixture 'cases' must be a list.")

    loader = PolicyLoader(search_paths=[fixture_path.parent, Path.cwd()])
    results = [_run_case(case, loader, fixture_path.parent) for case in raw_cases]
    return PolicySuiteResult(name=suite_name, results=results)


def explain_policy_event(policy_path: str | Path, event: dict[str, Any]) -> dict[str, Any]:
    policy = PolicyLoader().load(policy_path)
    capability, context, payload = normalize_event(event)
    explanation = policy.explain(capability, context, payload)
    verdict = display_verdict(explanation["verdict"])
    explanation.update(
        {
            "policy_file": str(policy_path),
            "capability": capability,
            "final_verdict": verdict,
        }
    )
    return explanation


def diff_policy_fixtures(
    before_policy_path: str | Path,
    after_policy_path: str | Path,
    fixture_path: str | Path,
) -> dict[str, Any]:
    before = PolicyLoader().load(before_policy_path)
    after = PolicyLoader().load(after_policy_path)
    fixture_data = load_fixture_file(fixture_path)
    cases = fixture_data.get("cases") or [fixture_data]

    transitions: dict[str, list[dict[str, Any]]] = {}
    newly_allowed: list[dict[str, Any]] = []
    for case in cases:
        capability, context, payload = normalize_event(case["event"])
        before_verdict = display_verdict(before.explain(capability, context, payload)["verdict"])
        after_verdict = display_verdict(after.explain(capability, context, payload)["verdict"])
        if before_verdict == after_verdict:
            continue

        transition = f"{before_verdict} -> {after_verdict}"
        entry = {
            "name": case.get("name", "unnamed"),
            "capability": capability,
            "before": before_verdict,
            "after": after_verdict,
        }
        transitions.setdefault(transition, []).append(entry)
        if after_verdict == "allow" and before_verdict != "allow":
            newly_allowed.append(entry)

    return {
        "before_policy": str(before_policy_path),
        "after_policy": str(after_policy_path),
        "fixture": str(fixture_path),
        "transitions": transitions,
        "newly_allowed": newly_allowed,
    }


def normalize_event(event: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    raw_action = event.get("action") or {}
    raw_actor = event.get("actor") or {}
    action = raw_action if isinstance(raw_action, dict) else {}
    actor = raw_actor if isinstance(raw_actor, dict) else {}
    payload = event.get("payload") or {}
    metadata = event.get("metadata") or {}
    action_name = action.get("name") or (raw_action if isinstance(raw_action, str) else None)
    actor_id = actor.get("id") or (raw_actor if isinstance(raw_actor, str) else None)
    capability = (
        action.get("capability")
        or metadata.get("capability")
        or event.get("capability")
        or f"{event.get('resource', '*')}.{event.get('operation', event.get('action_name', action_name or '*'))}.*"
    )
    context = {
        **metadata,
        "actor": actor_id or "unknown",
        "user_role": actor.get("role") or metadata.get("user_role"),
        "action": action_name or event.get("action_name"),
        "resource": event.get("resource"),
        "environment": event.get("environment") or metadata.get("environment") or "development",
        "tenant": event.get("tenant") or metadata.get("tenant"),
        "risk_level": event.get("risk_level") or metadata.get("risk_level"),
        "tool_name": event.get("tool_name") or payload.get("tool_name") or metadata.get("tool_name"),
    }
    return str(capability), context, dict(payload)


def _run_case(
    case: dict[str, Any],
    loader: PolicyLoader,
    fixture_dir: Path,
) -> PolicyFixtureResult:
    if "policy" not in case:
        raise ValueError("Policy fixture case requires a 'policy' field.")
    policy_path = Path(case["policy"])
    if not policy_path.is_absolute():
        policy_path = fixture_dir / policy_path

    policy = loader.load(policy_path)
    capability, context, payload = normalize_event(case["event"])
    explanation = policy.explain(capability, context, payload)
    actual = display_verdict(explanation["verdict"])
    expected = str((case.get("expected") or {}).get("verdict"))
    return PolicyFixtureResult(
        name=str(case.get("name") or "unnamed"),
        policy=str(policy_path),
        expected=expected,
        actual=actual,
        passed=actual == expected,
        reason=str(explanation.get("reason") or "policy_default_deny"),
        explanation=explanation,
    )
