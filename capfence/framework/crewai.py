"""CrewAI integration - CapFence tool wrapper.

Wraps CrewAI-style tools with deterministic runtime enforcement. The wrapper is
duck-typed so it can protect CrewAI `BaseTool` instances without importing CrewAI
at CapFence import time.
"""

from __future__ import annotations

from typing import Any

from capfence.core.runtime import ActionRuntime
from capfence.errors import AgentActionBlocked
from capfence.framework._base import _GuardedToolMixin

__all__ = ["CapFenceCrewAITool", "AgentActionBlocked"]


class CapFenceCrewAITool(_GuardedToolMixin):
    """Transparent wrapper adding CapFence enforcement to a CrewAI tool."""

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
        self._framework_name = "crewai"

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

        self.name = getattr(tool, "name", "unknown_tool")
        self.description = getattr(tool, "description", "")

    def run(self, tool_input: str | dict[str, Any], **kwargs: Any) -> Any:
        """Run the wrapped CrewAI tool after a gate check."""
        payload = self._build_payload(tool_input)
        self._check(payload)
        if hasattr(self._tool, "run"):
            return self._tool.run(tool_input, **kwargs)
        if callable(self._tool):
            return self._tool(tool_input, **kwargs)
        raise AgentActionBlocked(detail=f"Tool '{self.name}' has no run method")

    async def arun(self, tool_input: str | dict[str, Any], **kwargs: Any) -> Any:
        """Async variant for CrewAI tools exposing `arun`."""
        payload = self._build_payload(tool_input)
        await self._acheck(payload)
        if hasattr(self._tool, "arun"):
            return await self._tool.arun(tool_input, **kwargs)
        return self.run(tool_input, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._tool, name)
