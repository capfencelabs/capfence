"""Tests for lightweight framework adapters that avoid hard runtime deps."""

from __future__ import annotations

import pytest

from capfence import ActionRuntime, ApprovalEngine, AuditLogger, CapabilitySystem
from capfence.framework.autogen import CapFenceAutoGenTool
from capfence.framework.crewai import CapFenceCrewAITool
from capfence.framework.llamaindex import CapFenceLlamaIndexTool
from capfence.framework.pydanticai import CapFencePydanticTool
from capfence.errors import AgentActionBlocked


def _gate() -> ActionRuntime:
    caps = CapabilitySystem()
    caps.load_policy({
        "allow": ["safe.execute", "query.execute"],
        "deny": ["shell.execute"],
    })
    return ActionRuntime(
        capability_system=caps,
        approval_engine=ApprovalEngine(db_path=":memory:"),
        audit_trail=AuditLogger(db_path=":memory:"),
    )


class MockCrewTool:
    name = "safe"
    description = "safe tool"

    def run(self, tool_input, **kwargs):
        return f"crew:{tool_input}"


def test_crewai_adapter_allows_and_preserves_metadata():
    wrapped = CapFenceCrewAITool(MockCrewTool(), agent_id="agent", gate=_gate())
    assert wrapped.name == "safe"
    assert wrapped.run("hello") == "crew:hello"


def test_crewai_adapter_blocks():
    tool = MockCrewTool()
    tool.name = "shell"
    wrapped = CapFenceCrewAITool(tool, agent_id="agent", gate=_gate(), risk_category="execute")
    with pytest.raises(AgentActionBlocked):
        wrapped.run("rm -rf /")


def test_autogen_adapter_wraps_callable():
    def safe(value: str) -> str:
        return f"auto:{value}"

    wrapped = CapFenceAutoGenTool(safe, agent_id="agent", gate=_gate())
    assert wrapped("ok") == "auto:ok"


def test_autogen_adapter_blocks_callable():
    def shell(command: str) -> str:
        return command

    wrapped = CapFenceAutoGenTool(shell, agent_id="agent", gate=_gate())
    with pytest.raises(AgentActionBlocked):
        wrapped("rm -rf /")


class MockLlamaTool:
    name = "query"
    description = "query tool"

    def call(self, query: str) -> str:
        return f"llama:{query}"


def test_llamaindex_adapter_call():
    wrapped = CapFenceLlamaIndexTool(MockLlamaTool(), agent_id="agent", gate=_gate())
    assert wrapped.call("hello") == "llama:hello"
    assert wrapped("hello") == "llama:hello"


def test_pydanticai_adapter_wraps_callable():
    def safe(value: str) -> str:
        return f"pydantic:{value}"

    wrapped = CapFencePydanticTool(safe, agent_id="agent", gate=_gate())
    assert wrapped("ok") == "pydantic:ok"


def test_public_adapter_imports():
    import capfence.framework.autogen
    import capfence.framework.crewai
    import capfence.framework.llamaindex
    import capfence.framework.pydanticai

    assert capfence.framework.autogen.CapFenceAutoGenTool is CapFenceAutoGenTool
    assert capfence.framework.crewai.CapFenceCrewAITool is CapFenceCrewAITool
    assert capfence.framework.llamaindex.CapFenceLlamaIndexTool is CapFenceLlamaIndexTool
    assert capfence.framework.pydanticai.CapFencePydanticTool is CapFencePydanticTool
