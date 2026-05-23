"""External policy backend interfaces.

The local YAML policy engine remains the default. These backends provide an
integration path for teams that already centralize authorization in engines
such as OPA.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from capfence.core.policy import PolicyLoader


@dataclass(frozen=True)
class PolicyDecision:
    verdict: str
    reason: str
    matched_policy: dict[str, Any] = field(default_factory=dict)


class PolicyBackend(Protocol):
    def evaluate(
        self,
        capability: str,
        context: dict[str, Any],
        payload: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Return allow, deny, or require_approval for a normalized action."""


class YAMLPolicyBackend:
    """Default CapFence policy backend."""

    def __init__(self, policy_path: str | Path) -> None:
        self.policy_path = Path(policy_path)
        self.policy = PolicyLoader().load(self.policy_path)

    def evaluate(
        self,
        capability: str,
        context: dict[str, Any],
        payload: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        explanation = self.policy.explain(capability, context, payload)
        verdict = explanation["verdict"] or "deny"
        return PolicyDecision(
            verdict=verdict,
            reason=str(explanation.get("reason") or "policy_default_deny"),
            matched_policy=explanation,
        )


class OPAPolicyBackend:
    """OPA HTTP backend.

    Expected OPA response shape:
    {"result": {"verdict": "allow|deny|require_approval", "reason": "..."}}
    """

    def __init__(self, url: str, timeout_seconds: float = 2.0) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds

    def evaluate(
        self,
        capability: str,
        context: dict[str, Any],
        payload: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        request_body = json.dumps(
            {
                "input": {
                    "capability": capability,
                    "context": context,
                    "payload": payload or {},
                }
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=request_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (TimeoutError, urllib.error.URLError, json.JSONDecodeError) as exc:
            return PolicyDecision(
                verdict="deny",
                reason=f"opa_unavailable_fail_closed:{type(exc).__name__}",
            )

        result = raw.get("result") if isinstance(raw, dict) else None
        if not isinstance(result, dict):
            return PolicyDecision(verdict="deny", reason="opa_invalid_response_fail_closed")

        verdict = str(result.get("verdict") or "deny")
        if verdict not in {"allow", "deny", "require_approval"}:
            verdict = "deny"
        return PolicyDecision(
            verdict=verdict,
            reason=str(result.get("reason") or "opa_decision"),
            matched_policy=dict(result.get("matched_policy") or {}),
        )
