"""LangGraph integration — CapFence node wrapper.

Wraps LangGraph tool nodes with deterministic runtime enforcement.
"""

from __future__ import annotations

from typing import Any

from capfence.core.runtime import ActionRuntime, ActionEvent, ExecutionVerdict
from capfence.errors import AgentActionBlocked
from capfence.framework._risk import guess_risk_category

__all__ = ["CapFenceToolNode", "AgentActionBlocked"]


class CapFenceToolNode:
    """Wraps a LangGraph ToolNode with CapFence gate enforcement.

    Mirrors the LangGraph ToolNode interface for drop-in replacement.
    """

    def __init__(
        self,
        tools: list[Any],
        agent_id: str,
        gate: ActionRuntime | None = None,
        risk_category_map: dict[str, str] | None = None,
        capability_map: dict[str, str] | None = None,
        policy_path: str | None = None,
    ) -> None:
        self._tools = {t.name: t for t in tools}
        self._agent_id = agent_id
        self._risk_category_map = risk_category_map or {}
        self._capability_map = capability_map or {}
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

    def _get_risk_category(self, tool_name: str) -> str | None:
        """Explicit map first, then fall back to the shared keyword heuristic."""
        if tool_name in self._risk_category_map:
            return self._risk_category_map[tool_name]
        return guess_risk_category(tool_name)

    @staticmethod
    def _extract_calls(messages: list[Any]) -> list[dict[str, Any]]:
        tool_calls: list[dict[str, Any]] = []
        for msg in messages:
            if hasattr(msg, "tool_calls"):
                tool_calls.extend(msg.tool_calls)
            elif isinstance(msg, dict) and "tool_calls" in msg:
                tool_calls.extend(msg["tool_calls"])
        return tool_calls

    @staticmethod
    def _unpack_call(call: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
        tool_name = call.get("name", call.get("function", {}).get("name", "unknown"))
        arguments = call.get("args", call.get("arguments", {}))
        call_id = call.get("id", "unknown")
        return tool_name, arguments, call_id

    def _enforce(self, tool_name: str, arguments: dict[str, Any]) -> ExecutionVerdict:
        capability = self._capability_map.get(tool_name) or f"{tool_name}.execute"
        parts = capability.split(".", 1)
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else "execute"

        event = ActionEvent.create(
            actor=self._agent_id,
            action=action,
            resource=resource,
            environment="production",
            risk=self._get_risk_category(tool_name) or "medium",
            payload=arguments,
            capability=capability,
            tool_name=tool_name,
            risk_level=self._get_risk_category(tool_name) or "medium",
            framework="langgraph",
        )

        verdict = self._gate.execute(event)
        if not verdict.authorized:
            raise AgentActionBlocked(
                detail=f"Tool '{tool_name}' blocked: {verdict.reason}",
                gate_result=verdict,
            )
        return verdict

    async def _enforce_async(self, tool_name: str, arguments: dict[str, Any]) -> ExecutionVerdict:
        capability = self._capability_map.get(tool_name) or f"{tool_name}.execute"
        parts = capability.split(".", 1)
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else "execute"

        event = ActionEvent.create(
            actor=self._agent_id,
            action=action,
            resource=resource,
            environment="production",
            risk=self._get_risk_category(tool_name) or "medium",
            payload=arguments,
            capability=capability,
            tool_name=tool_name,
            risk_level=self._get_risk_category(tool_name) or "medium",
            framework="langgraph",
        )

        verdict = self._gate.execute(event)
        if not verdict.authorized:
            raise AgentActionBlocked(
                detail=f"Tool '{tool_name}' blocked: {verdict.reason}",
                gate_result=verdict,
            )
        return verdict

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """Execute tool calls from state['messages'] with gating."""
        results: list[Any] = []
        for call in self._extract_calls(state.get("messages", [])):
            tool_name, arguments, call_id = self._unpack_call(call)
            self._enforce(tool_name, arguments)
            tool = self._tools.get(tool_name)
            if tool is None:
                raise AgentActionBlocked(detail=f"Tool '{tool_name}' not found")
            tool_result = tool.invoke(arguments)
            results.append({"call_id": call_id, "tool_name": tool_name, "result": tool_result})
        return {**state, "tool_results": results}

    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
        """Async variant. Runs gate checks off the event loop and awaits
        ``tool.ainvoke`` when available, falling back to ``tool.invoke``."""
        results: list[Any] = []
        for call in self._extract_calls(state.get("messages", [])):
            tool_name, arguments, call_id = self._unpack_call(call)
            await self._enforce_async(tool_name, arguments)
            tool = self._tools.get(tool_name)
            if tool is None:
                raise AgentActionBlocked(detail=f"Tool '{tool_name}' not found")
            if hasattr(tool, "ainvoke"):
                tool_result = await tool.ainvoke(arguments)
            else:
                tool_result = tool.invoke(arguments)
            results.append({"call_id": call_id, "tool_name": tool_name, "result": tool_result})
        return {**state, "tool_results": results}
