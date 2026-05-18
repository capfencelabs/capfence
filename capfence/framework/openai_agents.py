"""OpenAI Agents SDK integration — CapFence tool wrapper.

Wraps OpenAI Agents SDK tools with deterministic runtime enforcement.
"""

from __future__ import annotations

from typing import Any, cast

from capfence.core.runtime import ActionRuntime, ActionEvent
from capfence.errors import AgentActionBlocked

__all__ = ["CapFenceOpenAITool", "AgentActionBlocked"]


class CapFenceOpenAITool:
    """Transparent wrapper adding deterministic gate enforcement to OpenAI Agents SDK tools.

    Mirrors the OpenAI Agents Tool interface for drop-in replacement.
    """

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

        if gate is None:
            if policy_path:
                self._gate = ActionRuntime.from_policy(policy_path)
            else:
                from capfence.core.capabilities import CapabilitySystem
                from capfence.core.approvals import ApprovalEngine
                from capfence.core.audit import AuditLogger
                self._gate = ActionRuntime(
                    capability_system=CapabilitySystem(),
                    approval_engine=ApprovalEngine(db_path=":memory:"),
                    audit_trail=AuditLogger(db_path=":memory:"),
                )
        else:
            self._gate = gate

        # Mirror tool metadata
        self.name = getattr(tool, "name", "unknown_tool")
        self.description = getattr(tool, "description", "")
        self.params_json_schema = getattr(tool, "params_json_schema", {})

    async def on_invoke_tool(self, context: Any, input_json: str) -> str:
        """Intercept tool invocation and evaluate through ActionRuntime."""
        import json
        try:
            arguments = json.loads(input_json)
        except json.JSONDecodeError:
            arguments = {"raw_input": input_json}

        capability = self._capability or f"{self.name}.execute"
        parts = capability.split(".", 1)
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else "execute"

        event = ActionEvent.create(
            actor=self._agent_id,
            action=action,
            resource=resource,
            environment="production",
            risk=self._risk_category or "medium",
            payload=arguments,
        )

        verdict = self._gate.execute(event)
        if not verdict.authorized:
            raise AgentActionBlocked(
                detail=f"Tool '{self.name}' blocked: {verdict.reason}",
                gate_result=verdict,
            )

        # Forward to underlying tool
        if hasattr(self._tool, "on_invoke_tool"):
            return cast(str, await self._tool.on_invoke_tool(context, input_json))
        elif hasattr(self._tool, "invoke"):
            return str(self._tool.invoke(arguments))
        else:
            raise AgentActionBlocked(detail=f"Tool '{self.name}' has no invoke method")

    def __getattr__(self, name: str) -> Any:
        """Transparent passthrough for tool attributes."""
        return getattr(self._tool, name)
