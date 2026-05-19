"""Shared helpers for framework adapters.

The single-tool adapters (LangChain, CrewAI) all do the same three things:
build a payload dict from heterogeneous tool input, run a sync gate check,
or run an async gate check. This mixin centralises that logic so each
adapter only implements the framework-specific run/arun glue.
"""
from __future__ import annotations

from typing import Any

from capfence.core.runtime import ActionRuntime, ActionEvent
from capfence.errors import AgentActionBlocked


class _GuardedToolMixin:
    """Provides `_build_payload`, `_check`, `_acheck` to single-tool adapters.

    Subclasses must set: ``_gate``, ``_agent_id``,
    ``_risk_category``, and ``name``.
    """

    _gate: ActionRuntime
    _agent_id: str
    _risk_category: str | None
    _capability: str | None
    _policy_path: str | None
    name: str

    @staticmethod
    def _build_payload(tool_input: str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(tool_input, str):
            return {"input": tool_input}
        return dict(tool_input)

    def _check(self, payload: dict[str, Any]) -> None:
        capability = getattr(self, "_capability", None) or f"{self.name}.execute"
        parts = capability.split(".", 1)
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else "execute"

        event = ActionEvent.create(
            actor=self._agent_id,
            action=action,
            resource=resource,
            environment="production",
            risk=self._risk_category or "medium",
            payload=payload,
            capability=capability,
            tool_name=self.name,
            risk_level=self._risk_category or "medium",
            framework="langchain",
        )

        verdict = self._gate.execute(event)
        if not verdict.authorized:
            raise AgentActionBlocked(
                detail=f"Blocked: {verdict.reason}",
                gate_result=verdict
            )

    async def _acheck(self, payload: dict[str, Any]) -> None:
        capability = getattr(self, "_capability", None) or f"{self.name}.execute"
        parts = capability.split(".", 1)
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else "execute"

        event = ActionEvent.create(
            actor=self._agent_id,
            action=action,
            resource=resource,
            environment="production",
            risk=self._risk_category or "medium",
            payload=payload,
            capability=capability,
            tool_name=self.name,
            risk_level=self._risk_category or "medium",
            framework="langchain",
        )

        verdict = self._gate.execute(event)
        if not verdict.authorized:
            raise AgentActionBlocked(
                detail=f"Blocked: {verdict.reason}",
                gate_result=verdict
            )
