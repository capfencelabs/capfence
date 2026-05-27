"""LlamaIndex integration - CapFence tool wrapper."""

from __future__ import annotations

from typing import Any

from capfence.core.runtime import ActionEvent, ActionRuntime
from capfence.errors import AgentActionBlocked

__all__ = ["CapFenceLlamaIndexTool", "AgentActionBlocked"]


class CapFenceLlamaIndexTool:
    """Wrap LlamaIndex tools exposing `call`, `acall`, or `__call__`."""

    def __init__(
        self,
        tool: Any,
        agent_id: str,
        risk_category: str | None = None,
        capability: str | None = None,
        policy_path: str | None = None,
        gate: ActionRuntime | None = None,
    ) -> None:
        self._tool = tool
        self._agent_id = agent_id
        self._risk_category = risk_category
        self._capability = capability
        self._policy_path = policy_path
        metadata = getattr(tool, "metadata", None)
        self.name = getattr(metadata, "name", None) or getattr(tool, "name", "unknown_tool")
        self.description = getattr(metadata, "description", None) or getattr(tool, "description", "")

        if gate is None:
            if policy_path:
                self._gate = ActionRuntime.from_policy(policy_path)
            else:
                from capfence.core.approvals import ApprovalEngine
                from capfence.core.audit import AuditLogger
                from capfence.core.capabilities import CapabilitySystem

                self._gate = ActionRuntime(
                    capability_system=CapabilitySystem(),
                    approval_engine=ApprovalEngine(db_path=":memory:"),
                    audit_trail=AuditLogger(db_path=":memory:"),
                )
        else:
            self._gate = gate

    def _payload(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
        return {"args": list(args), "kwargs": kwargs}

    def _check(self, payload: dict[str, Any]) -> None:
        capability = self._capability or f"{self.name}.execute"
        parts = capability.split(".", 1)
        event = ActionEvent.create(
            actor=self._agent_id,
            action=parts[1] if len(parts) > 1 else "execute",
            resource=parts[0],
            environment="production",
            risk=self._risk_category or "medium",
            payload=payload,
            capability=capability,
            tool_name=self.name,
            risk_level=self._risk_category or "medium",
            framework="llamaindex",
        )
        verdict = self._gate.execute(event)
        if not verdict.authorized:
            raise AgentActionBlocked(
                detail=f"Tool '{self.name}' blocked: {verdict.reason}",
                gate_result=verdict,
            )

    def call(self, *args: Any, **kwargs: Any) -> Any:
        self._check(self._payload(args, kwargs))
        if hasattr(self._tool, "call"):
            return self._tool.call(*args, **kwargs)
        if callable(self._tool):
            return self._tool(*args, **kwargs)
        raise AgentActionBlocked(detail=f"Tool '{self.name}' has no call method")

    async def acall(self, *args: Any, **kwargs: Any) -> Any:
        self._check(self._payload(args, kwargs))
        if hasattr(self._tool, "acall"):
            return await self._tool.acall(*args, **kwargs)
        return self.call(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.call(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tool, name)
