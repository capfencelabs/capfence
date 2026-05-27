"""AutoGen integration - CapFence callable wrapper."""

from __future__ import annotations

from typing import Any, Callable

from capfence.core.runtime import ActionEvent, ActionRuntime
from capfence.errors import AgentActionBlocked

__all__ = ["CapFenceAutoGenTool", "AgentActionBlocked"]


class CapFenceAutoGenTool:
    """Wrap an AutoGen tool callable with CapFence enforcement."""

    def __init__(
        self,
        tool: Callable[..., Any],
        agent_id: str,
        name: str | None = None,
        description: str | None = None,
        risk_category: str | None = None,
        capability: str | None = None,
        policy_path: str | None = None,
        gate: ActionRuntime | None = None,
        framework_name: str = "autogen",
    ) -> None:
        self._tool = tool
        self._agent_id = agent_id
        self._risk_category = risk_category
        self._capability = capability
        self._policy_path = policy_path
        self._framework_name = framework_name
        self.name = name or getattr(tool, "__name__", "unknown_tool")
        self.description = description or getattr(tool, "__doc__", "") or ""

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

    def _check(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        capability = self._capability or f"{self.name}.execute"
        parts = capability.split(".", 1)
        event = ActionEvent.create(
            actor=self._agent_id,
            action=parts[1] if len(parts) > 1 else "execute",
            resource=parts[0],
            environment="production",
            risk=self._risk_category or "medium",
            payload={"args": list(args), "kwargs": kwargs},
            capability=capability,
            tool_name=self.name,
            risk_level=self._risk_category or "medium",
            framework=self._framework_name,
        )
        verdict = self._gate.execute(event)
        if not verdict.authorized:
            raise AgentActionBlocked(
                detail=f"Tool '{self.name}' blocked: {verdict.reason}",
                gate_result=verdict,
            )

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._check(args, kwargs)
        return self._tool(*args, **kwargs)
