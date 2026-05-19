"""Example: LangGraph integration with CapFence (Week 10).

Demonstrates CapFenceToolNode for LangGraph ToolNode replacement.
"""

from capfence.framework.langgraph import CapFenceToolNode
from capfence import ActionRuntime, ApprovalEngine, AuditLogger, CapabilitySystem


class MockLangGraphTool:
    """Mock LangChain tool for demo."""

    def __init__(self, name: str):
        self.name = name

    def invoke(self, arguments: dict):
        return f"Result from {self.name}: {arguments}"


def main():
    # Create tools
    read_tool = MockLangGraphTool("read_balance")
    shell_tool = MockLangGraphTool("shell")
    pay_tool = MockLangGraphTool("pay_vendor")

    # Create CapFence-wrapped node
    caps = CapabilitySystem()
    caps.load_policy({
        "allow": ["read_balance.execute"],
        "deny": ["shell.execute"],
        "require_approval": ["pay_vendor.execute"],
    })
    gate = ActionRuntime(
        capability_system=caps,
        approval_engine=ApprovalEngine(db_path=":memory:"),
        audit_trail=AuditLogger(db_path=":memory:"),
    )
    node = CapFenceToolNode(
        tools=[read_tool, shell_tool, pay_tool],
        agent_id="langgraph-agent-1",
        gate=gate,
        risk_category_map={
            "read_balance": "read_only",
            "shell": "execute",
            "pay_vendor": "payment_initiation",
        },
    )

    print("LangGraph CapFenceToolNode")
    print("=" * 40)
    print(f"Agent ID: {node._agent_id}")
    print(f"Tools: {list(node._tools.keys())}")
    print(f"Risk categories: {node._risk_category_map}")

    # Test safe call (read_balance)
    print("\nTest 1: read_balance (safe)")
    safe_state = {
        "messages": [
            type("Msg", (), {
                "tool_calls": [{"name": "read_balance", "args": {"account": "123"}, "id": "1"}],
            })()
        ]
    }
    try:
        result = node(safe_state)
        print(f"  Result: {result['tool_results']}")
    except Exception as e:
        print(f"  Blocked: {e}")

    # Test blocked call (shell)
    print("\nTest 2: shell (blocked)")
    dangerous_state = {
        "messages": [
            type("Msg", (), {
                "tool_calls": [{"name": "shell", "args": {"command": "execute rm -rf /"}, "id": "2"}],
            })()
        ]
    }
    try:
        result = node(dangerous_state)
        print(f"  Result: {result}")
    except Exception as e:
        print(f"  Blocked: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
