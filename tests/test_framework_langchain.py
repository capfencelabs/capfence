"""Tests for LangChain CapFenceTool wrapper."""

import pytest
from capfence import ActionRuntime, ExecutionVerdict
from capfence.framework.langchain import CapFenceTool, AgentActionBlocked, capfence_guard


class MockTool:
    """Simple mock tool for testing."""
    name = "mock"
    description = "Mock tool"

    def run(self, tool_input, **kwargs):
        return f"result: {tool_input}"


@pytest.fixture
def runtime_gate(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
deny:
  - capability: mock.execute
    contains: "delete"
  - capability: risky_delete.execute

allow:
  - capability: mock.execute
    contains: "view"
  - capability: safe_view.execute
""",
        encoding="utf-8",
    )
    return ActionRuntime.from_policy(policy_path)


class TestCapFenceTool:
    def test_passes_allows_execution(self, runtime_gate):
        tool = CapFenceTool(
            tool=MockTool(),
            agent_id="test-agent",
            risk_category="low",
            gate=runtime_gate,
        )
        result = tool.run("view dashboard")
        assert "result:" in result

    def test_blocks_on_risk(self, runtime_gate):
        tool = CapFenceTool(
            tool=MockTool(),
            agent_id="test-agent",
            risk_category="high",
            gate=runtime_gate,
        )
        with pytest.raises(AgentActionBlocked) as exc_info:
            tool.run("delete all records and drop tables")

        assert "blocked" in exc_info.value.detail.lower()
        assert exc_info.value.gate_result is not None

    def test_preserves_tool_attributes(self, runtime_gate):
        tool = CapFenceTool(
            tool=MockTool(),
            agent_id="test",
            risk_category="low",
            gate=runtime_gate,
        )
        assert tool.name == "mock"
        assert tool.description == "Mock tool"

    def test_metadata_in_exception(self, runtime_gate):
        tool = CapFenceTool(
            tool=MockTool(),
            agent_id="test-agent",
            risk_category="critical",
            gate=runtime_gate,
        )
        with pytest.raises(AgentActionBlocked) as exc_info:
            # Contains delete to trigger block
            tool.run("delete rm -rf /")

        assert exc_info.value.gate_result is not None
        assert exc_info.value.gate_result.metadata is not None
        assert "latency_ms" in exc_info.value.gate_result.metadata


class TestGuardDecorator:
    def test_decorator_blocks(self, runtime_gate):
        @capfence_guard(agent_id="test-agent", risk_category="high", gate=runtime_gate)
        def risky_delete(id: str) -> str:
            return f"deleted {id}"

        with pytest.raises(AgentActionBlocked):
            risky_delete("delete drop remove all records")

    def test_decorator_allows(self, runtime_gate):
        @capfence_guard(agent_id="test-agent", risk_category="low", gate=runtime_gate)
        def safe_view(id: str) -> str:
            return f"viewed {id}"

        result = safe_view("record-123")
        assert result == "viewed record-123"
