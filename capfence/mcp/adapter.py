"""In-process MCP adapter for CapFence.

Wraps an MCP client session so that every tool call is gated
before execution. This is the in-process equivalent of the
stdio proxy gateway.
"""

from __future__ import annotations

import logging
from typing import Any

from capfence.core.runtime import ActionRuntime, ActionEvent
from capfence.errors import AgentActionBlocked
from capfence.framework._risk import guess_risk_category

logger = logging.getLogger(__name__)

__all__ = ["CapFenceMCPSession", "AgentActionBlocked"]


class CapFenceMCPSession:
    """Wraps an MCP client session with CapFence gating.

    Transparent passthrough for all methods except tool calls.
    """

    def __init__(
        self,
        underlying_session: Any,
        gate: ActionRuntime | None = None,
        agent_id: str = "mcp-agent",
        default_risk_category: str | None = None,
    ) -> None:
        self._session = underlying_session
        self._agent_id = agent_id
        self._default_risk_category = default_risk_category

        if gate is None:
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

    def __getattr__(self, name: str) -> Any:
        """Transparent passthrough for non-wrapped methods."""
        return getattr(self._session, name)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call a tool through the CapFence gate."""
        risk_category = self._default_risk_category or self._guess_category(name)
        
        capability = "mcp.tool.execute"
        parts = capability.split(".", 1)
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else "execute"
        risk_level = risk_category or "medium"

        event = ActionEvent.create(
            actor=self._agent_id,
            action=action,
            resource=resource,
            environment="production",
            risk=risk_level,
            payload=arguments or {},
            capability=capability,
            tool_name=name,
            risk_level=risk_level,
            framework="mcp",
        )

        verdict = self._gate.execute(event)
        if not verdict.authorized:
            logger.warning(
                "Blocked MCP tool call: %s (decision=%s, reason=%s)",
                name, verdict.decision, verdict.reason,
            )
            raise AgentActionBlocked(
                detail=f"Tool '{name}' blocked: {verdict.reason}",
                gate_result=verdict,
            )
        # Forward to underlying session
        return await self._session.call_tool(name, arguments)

    _guess_category = staticmethod(guess_risk_category)
