"""Tests for MCP gateway and adapter."""

from __future__ import annotations

from capfence import ActionRuntime, ExecutionVerdict, ActionEvent
from capfence.mcp.gateway import MCPGatewayServer
from capfence.mcp.adapter import CapFenceMCPSession, AgentActionBlocked


class TestMCPGatewayServer:
    """Tests for MCPGatewayServer."""

    def test_init_defaults(self):
        gw = MCPGatewayServer(upstream_command=["echo", "test"])
        assert gw._agent_id == "mcp-gateway"
        assert gw._default_risk_category is None
        assert isinstance(gw._gate, ActionRuntime)

    def test_init_custom(self):
        from capfence.core.capabilities import CapabilitySystem
        from capfence.core.approvals import ApprovalEngine
        from capfence.core.audit import AuditLogger
        gate = ActionRuntime(
            capability_system=CapabilitySystem(),
            approval_engine=ApprovalEngine(db_path=":memory:"),
            audit_trail=AuditLogger(db_path=":memory:"),
        )
        gw = MCPGatewayServer(
            upstream_command=["echo", "test"],
            gate=gate,
            agent_id="custom-agent",
            default_risk_category="execute",
        )
        assert gw._agent_id == "custom-agent"
        assert gw._default_risk_category == "execute"
        assert gw._gate is gate

    def test_is_tool_call_true(self):
        gw = MCPGatewayServer(upstream_command=["echo", "test"])
        assert gw._is_tool_call({"method": "tools/call"}) is True
        assert gw._is_tool_call({"method": "tool/call"}) is True
        assert gw._is_tool_call({"method": "call_tool"}) is True

    def test_is_tool_call_false(self):
        gw = MCPGatewayServer(upstream_command=["echo", "test"])
        assert gw._is_tool_call({"method": "initialize"}) is False
        assert gw._is_tool_call({"method": "tools/list"}) is False
        assert gw._is_tool_call({}) is False

    def test_extract_tool_payload(self):
        gw = MCPGatewayServer(upstream_command=["echo", "test"])
        msg = {
            "method": "tools/call",
            "params": {
                "name": "shell",
                "arguments": {"command": "ls"},
            },
        }
        payload = gw._extract_tool_payload(msg)
        assert payload["tool_name"] == "shell"
        assert payload["arguments"] == {"command": "ls"}

    def test_extract_tool_payload_unknown(self):
        gw = MCPGatewayServer(upstream_command=["echo", "test"])
        msg = {"method": "tools/call", "params": {}}
        payload = gw._extract_tool_payload(msg)
        assert payload["tool_name"] == "unknown"
        assert payload["arguments"] == {}

    def test_build_blocked_response(self):
        gw = MCPGatewayServer(upstream_command=["echo", "test"])
        event = ActionEvent.create(
            actor="agent",
            action="execute",
            resource="shell",
            environment="production",
            risk=0.8,
        )
        verdict = ExecutionVerdict(
            authorized=False,
            decision="deny",
            reason="drift_detected",
            event=event,
            timestamp=123.456,
        )
        response = gw._build_blocked_response({"id": 1}, verdict)
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert response["error"]["code"] == -32000
        assert "CapFence" in response["error"]["message"]
        assert response["error"]["data"]["risk_score"] == 0.8

    def test_guess_category_shell(self):
        assert MCPGatewayServer._guess_category("shell") == "command_execution"
        assert MCPGatewayServer._guess_category("run_command") == "command_execution"
        assert MCPGatewayServer._guess_category("bash_tool") == "command_execution"

    def test_guess_category_payment(self):
        assert MCPGatewayServer._guess_category("pay") == "payment_initiation"
        assert MCPGatewayServer._guess_category("stripe_transfer") == "payment_initiation"
        assert MCPGatewayServer._guess_category("disburse_funds") == "payment_initiation"

    def test_guess_category_delete(self):
        assert MCPGatewayServer._guess_category("delete_file") == "delete"
        assert MCPGatewayServer._guess_category("remove_user") == "delete"
        assert MCPGatewayServer._guess_category("drop_table") == "delete"

    def test_guess_category_write(self):
        assert MCPGatewayServer._guess_category("write_file") == "write"
        assert MCPGatewayServer._guess_category("update_record") == "write"
        assert MCPGatewayServer._guess_category("modify_config") == "write"

    def test_guess_category_read(self):
        assert MCPGatewayServer._guess_category("read_file") == "read_only"
        assert MCPGatewayServer._guess_category("get_users") == "read_only"
        assert MCPGatewayServer._guess_category("list_items") == "read_only"
        assert MCPGatewayServer._guess_category("view_logs") == "read_only"
        assert MCPGatewayServer._guess_category("query_db") == "read_only"

    def test_guess_category_unknown(self):
        assert MCPGatewayServer._guess_category("unknown_tool") is None
        assert MCPGatewayServer._guess_category("xyz") is None


class TestCapFenceMCPSession:
    """Tests for CapFenceMCPSession."""

    def test_init_defaults(self):
        session = CapFenceMCPSession(underlying_session=None)
        assert session._agent_id == "mcp-agent"
        assert session._default_risk_category is None
        assert isinstance(session._gate, ActionRuntime)

    def test_init_custom(self):
        from capfence.core.capabilities import CapabilitySystem
        from capfence.core.approvals import ApprovalEngine
        from capfence.core.audit import AuditLogger
        gate = ActionRuntime(
            capability_system=CapabilitySystem(),
            approval_engine=ApprovalEngine(db_path=":memory:"),
            audit_trail=AuditLogger(db_path=":memory:"),
        )
        session = CapFenceMCPSession(
            underlying_session=None,
            gate=gate,
            agent_id="custom-agent",
            default_risk_category="execute",
        )
        assert session._agent_id == "custom-agent"
        assert session._default_risk_category == "execute"
        assert session._gate is gate

    def test_guess_category_shell(self):
        assert CapFenceMCPSession._guess_category("shell") == "command_execution"
        assert CapFenceMCPSession._guess_category("exec_tool") == "command_execution"

    def test_guess_category_payment(self):
        assert CapFenceMCPSession._guess_category("pay") == "payment_initiation"
        assert CapFenceMCPSession._guess_category("transfer_funds") == "payment_initiation"

    def test_guess_category_delete(self):
        assert CapFenceMCPSession._guess_category("delete") == "delete"
        assert CapFenceMCPSession._guess_category("remove") == "delete"

    def test_guess_category_write(self):
        assert CapFenceMCPSession._guess_category("write") == "write"
        assert CapFenceMCPSession._guess_category("update") == "write"

    def test_guess_category_read(self):
        assert CapFenceMCPSession._guess_category("read") == "read_only"
        assert CapFenceMCPSession._guess_category("get") == "read_only"

    def test_guess_category_unknown(self):
        assert CapFenceMCPSession._guess_category("unknown") is None

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

    def test_agent_action_blocked_no_result(self):
        exc = AgentActionBlocked(detail="blocked")
        assert exc.detail == "blocked"
        assert exc.gate_result is None
