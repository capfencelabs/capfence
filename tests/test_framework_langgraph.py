"""Tests for LangGraph adapter."""

from __future__ import annotations

import pytest

from capfence import ActionRuntime, ExecutionVerdict, ActionEvent
from capfence.framework.langgraph import CapFenceToolNode, AgentActionBlocked


class MockTool:
    """Mock LangChain tool for testing."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description

    def invoke(self, arguments: dict) -> str:
        return f"invoked {self.name} with {arguments}"


class TestCapFenceToolNode:
    """Tests for CapFenceToolNode."""

    def test_init_defaults(self):
        tools = [MockTool("read_tool")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        assert node._agent_id == "agent-1"
        assert "read_tool" in node._tools
        assert isinstance(node._gate, ActionRuntime)

    def test_init_custom_gate(self):
        from capfence.core.capabilities import CapabilitySystem
        from capfence.core.approvals import ApprovalEngine
        from capfence.core.audit import AuditLogger
        gate = ActionRuntime(
            capability_system=CapabilitySystem(),
            approval_engine=ApprovalEngine(db_path=":memory:"),
            audit_trail=AuditLogger(db_path=":memory:"),
        )
        tools = [MockTool("read_tool")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1", gate=gate)
        assert node._gate is gate

    def test_init_with_risk_category_map(self):
        tools = [MockTool("my_tool")]
        node = CapFenceToolNode(
            tools=tools,
            agent_id="agent-1",
            risk_category_map={"my_tool": "execute"},
        )
        assert node._get_risk_category("my_tool") == "execute"

    def test_get_risk_category_from_map(self):
        tools = [MockTool("shell")]
        node = CapFenceToolNode(
            tools=tools,
            agent_id="agent-1",
            risk_category_map={"shell": "command_execution"},
        )
        assert node._get_risk_category("shell") == "command_execution"

    def test_get_risk_category_heuristic_shell(self):
        tools = [MockTool("shell")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        assert node._get_risk_category("shell") == "command_execution"
        assert node._get_risk_category("exec_tool") == "command_execution"
        assert node._get_risk_category("run_command") == "command_execution"
        assert node._get_risk_category("bash") == "command_execution"

    def test_get_risk_category_heuristic_payment(self):
        tools = [MockTool("pay")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        assert node._get_risk_category("pay") == "payment_initiation"
        assert node._get_risk_category("transfer") == "payment_initiation"
        assert node._get_risk_category("stripe_charge") == "payment_initiation"

    def test_get_risk_category_heuristic_delete(self):
        tools = [MockTool("delete")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        assert node._get_risk_category("delete") == "delete"
        assert node._get_risk_category("remove") == "delete"
        assert node._get_risk_category("drop") == "delete"

    def test_get_risk_category_heuristic_write(self):
        tools = [MockTool("write")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        assert node._get_risk_category("write") == "write"
        assert node._get_risk_category("update") == "write"
        assert node._get_risk_category("modify") == "write"

    def test_get_risk_category_heuristic_read(self):
        tools = [MockTool("read")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        assert node._get_risk_category("read") == "read_only"
        assert node._get_risk_category("get") == "read_only"
        assert node._get_risk_category("list") == "read_only"
        assert node._get_risk_category("view") == "read_only"
        assert node._get_risk_category("query") == "read_only"

    def test_get_risk_category_unknown(self):
        tools = [MockTool("unknown")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        assert node._get_risk_category("unknown") is None

    def test_call_passes_safe_tool(self):
        tools = [MockTool("read_tool")]
        from capfence.core.capabilities import CapabilitySystem
        from capfence.core.approvals import ApprovalEngine
        from capfence.core.audit import AuditLogger
        caps = CapabilitySystem()
        caps.load_policy({"allow": ["read_tool.execute"]})
        gate = ActionRuntime(
            capability_system=caps,
            approval_engine=ApprovalEngine(db_path=":memory:"),
            audit_trail=AuditLogger(db_path=":memory:"),
        )
        node = CapFenceToolNode(tools=tools, agent_id="agent-1", gate=gate)
        state = {
            "messages": [
                type("Msg", (), {
                    "tool_calls": [{"name": "read_tool", "args": {}, "id": "1"}],
                })()
            ]
        }
        result = node(state)
        assert "tool_results" in result
        assert len(result["tool_results"]) == 1
        assert result["tool_results"][0]["tool_name"] == "read_tool"

    def test_call_blocks_high_risk_tool(self, tmp_path):
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            """
deny:
  - capability: shell.execute
    contains: "rm -rf"
""",
            encoding="utf-8",
        )
        gate = ActionRuntime.from_policy(policy_path)
        tools = [MockTool("shell")]
        node = CapFenceToolNode(
            tools=tools,
            agent_id="agent-1",
            risk_category_map={"shell": "execute"},
            gate=gate,
        )
        state = {
            "messages": [
                type("Msg", (), {
                    "tool_calls": [{"name": "shell", "args": {"command": "execute rm -rf /"}, "id": "1"}],
                })()
            ]
        }
        with pytest.raises(AgentActionBlocked):
            node(state)

    def test_call_unknown_tool_raises(self):
        tools = [MockTool("read_tool")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        state = {
            "messages": [
                type("Msg", (), {
                    "tool_calls": [{"name": "nonexistent", "args": {}, "id": "1"}],
                })()
            ]
        }
        with pytest.raises(AgentActionBlocked):
            node(state)

    def test_call_dict_messages(self):
        tools = [MockTool("read_tool")]
        from capfence.core.capabilities import CapabilitySystem
        from capfence.core.approvals import ApprovalEngine
        from capfence.core.audit import AuditLogger
        caps = CapabilitySystem()
        caps.load_policy({"allow": ["read_tool.execute"]})
        gate = ActionRuntime(
            capability_system=caps,
            approval_engine=ApprovalEngine(db_path=":memory:"),
            audit_trail=AuditLogger(db_path=":memory:"),
        )
        node = CapFenceToolNode(tools=tools, agent_id="agent-1", gate=gate)
        state = {
            "messages": [
                {"tool_calls": [{"name": "read_tool", "args": {}, "id": "1"}]}
            ]
        }
        result = node(state)
        assert "tool_results" in result
        assert len(result["tool_results"]) == 1

    def test_call_no_messages(self):
        tools = [MockTool("read_tool")]
        node = CapFenceToolNode(tools=tools, agent_id="agent-1")
        result = node({})
        assert "tool_results" in result
        assert result["tool_results"] == []

    def test_agent_action_blocked_exception(self):
        event = ActionEvent.create(
            actor="agent",
            action="execute",
            resource="shell",
            environment="production",
        )
        result = ExecutionVerdict(
            authorized=False,
            decision="deny",
            reason="test",
            event=event,
            timestamp=123.456,
        )
        exc = AgentActionBlocked(detail="blocked", gate_result=result)
        assert exc.detail == "blocked"
        assert exc.gate_result is result
        assert str(exc) == "blocked"
