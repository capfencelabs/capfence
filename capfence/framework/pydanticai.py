"""PydanticAI integration - CapFence callable wrapper."""

from __future__ import annotations

from typing import Any, Callable

from capfence.framework.autogen import CapFenceAutoGenTool

__all__ = ["CapFencePydanticTool", "AgentActionBlocked"]

from capfence.errors import AgentActionBlocked


class CapFencePydanticTool(CapFenceAutoGenTool):
    """Wrap a PydanticAI tool callable with CapFence enforcement."""

    def __init__(
        self,
        tool: Callable[..., Any],
        agent_id: str,
        name: str | None = None,
        description: str | None = None,
        risk_category: str | None = None,
        capability: str | None = None,
        policy_path: str | None = None,
        gate: Any = None,
    ) -> None:
        super().__init__(
            tool=tool,
            agent_id=agent_id,
            name=name,
            description=description,
            risk_category=risk_category,
            capability=capability,
            policy_path=policy_path,
            gate=gate,
            framework_name="pydanticai",
        )
