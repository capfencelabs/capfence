"""LangChain integration — CapFence tool wrapper and decorator.

Wraps LangChain tool classes and functions with deterministic runtime enforcement.
"""

from __future__ import annotations

from typing import Any, Callable

from capfence.core.runtime import ActionRuntime, ActionEvent
from capfence.errors import AgentActionBlocked
from capfence.framework._base import _GuardedToolMixin

__all__ = ["CapFenceTool", "AgentActionBlocked", "capfence_guard"]


class CapFenceTool(_GuardedToolMixin):
    """Transparent wrapper adding deterministic gate enforcement to any tool.

    Implements the same interface as the wrapped tool for drop-in replacement.
    """

    def __init__(
        self,
        tool: Any,  # BaseTool or duck-typed
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

    def run(self, tool_input: str | dict[str, Any], **kwargs: Any) -> Any:
        """Run the wrapped tool after a synchronous gate check."""
        payload = self._build_payload(tool_input)
        self._check(payload)
        return self._tool.run(tool_input, **kwargs)

    async def arun(self, tool_input: str | dict[str, Any], **kwargs: Any) -> Any:
        """Async variant. Runs the gate check off the event loop, then awaits
        the wrapped tool's ``arun`` if it has one (otherwise falls back to sync ``run``)."""
        payload = self._build_payload(tool_input)
        await self._acheck(payload)
        if hasattr(self._tool, "arun"):
            return await self._tool.arun(tool_input, **kwargs)
        return self._tool.run(tool_input, **kwargs)

    def __getattr__(self, name: str) -> Any:
        # Transparent passthrough for tool attributes
        return getattr(self._tool, name)


# Convenience decorator for function tools

def capfence_guard(
    agent_id: str,
    risk_category: str | None = None,
    capability: str | None = None,
    policy_path: str | None = None,
    gate: ActionRuntime | None = None,
) -> Callable[..., Any]:
    """Decorator factory for function-based LangChain tools.

    Usage:
        @capfence_guard(agent_id="finance-1", risk_category="disbursement")
        def disburse_funds(account: str, amount: float) -> str:
            ...
    """
    if gate is None:
        if policy_path:
            _gate = ActionRuntime.from_policy(policy_path)
        else:
            from capfence.core.capabilities import CapabilitySystem
            from capfence.core.approvals import ApprovalEngine
            from capfence.core.audit import AuditLogger
            _gate = ActionRuntime(
                capability_system=CapabilitySystem(),
                approval_engine=ApprovalEngine(db_path=":memory:"),
                audit_trail=AuditLogger(db_path=":memory:"),
            )
    else:
        _gate = gate

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            payload = {"args": args, "kwargs": kwargs, "task_context": func.__name__}
            
            capability_str = capability or f"{func.__name__}.execute"
            parts = capability_str.split(".", 1)
            resource = parts[0]
            action = parts[1] if len(parts) > 1 else "execute"

            event = ActionEvent.create(
                actor=agent_id,
                action=action,
                resource=resource,
                environment="production",
                risk=risk_category or "medium",
                payload=payload,
            )

            verdict = _gate.execute(event)
            if not verdict.authorized:
                raise AgentActionBlocked(
                    detail=f"Blocked: {verdict.reason}",
                    gate_result=verdict
                )
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    return decorator
