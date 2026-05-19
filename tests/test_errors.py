"""Tests for the unified exception hierarchy."""

import capfence
from capfence.errors import (
    AgentActionBlocked,
    ConfigurationError,
    CapFenceError,
)
from capfence.framework.langchain import AgentActionBlocked as LCBlocked
from capfence.framework.langgraph import AgentActionBlocked as LGBlocked
from capfence.framework.openai_agents import AgentActionBlocked as OAIBlocked
from capfence.mcp.adapter import AgentActionBlocked as MCPBlocked


def test_version_exposed():
    assert isinstance(capfence.__version__, str)
    assert capfence.__version__.count(".") >= 1


def test_all_framework_agent_blocked_is_same_class():
    """A user catching capfence.AgentActionBlocked must catch every adapter's block."""
    assert LCBlocked is AgentActionBlocked
    assert LGBlocked is AgentActionBlocked
    assert OAIBlocked is AgentActionBlocked
    assert MCPBlocked is AgentActionBlocked
    assert capfence.AgentActionBlocked is AgentActionBlocked


def test_agent_blocked_inherits_capfence_error():
    exc = AgentActionBlocked(detail="blocked")
    assert isinstance(exc, CapFenceError)


def test_configuration_error_keeps_value_error_compat():
    """Existing code that catches ValueError on bad config must keep working."""
    err = ConfigurationError("bad mode")
    assert isinstance(err, ValueError)
    assert isinstance(err, CapFenceError)


def test_agent_blocked_carries_detail_and_result():
    exc = AgentActionBlocked(detail="payout too large")
    assert exc.detail == "payout too large"
    assert exc.gate_result is None
    assert str(exc) == "payout too large"
