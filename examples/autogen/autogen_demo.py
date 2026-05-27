"""Minimal AutoGen integration demo."""
from capfence import ActionRuntime, ApprovalEngine, AuditLogger, CapabilitySystem
from capfence.errors import AgentActionBlocked
from capfence.framework.autogen import CapFenceAutoGenTool

caps = CapabilitySystem()
caps.load_policy({"deny": ["shell.execute"]})
runtime = ActionRuntime(
    capability_system=caps,
    approval_engine=ApprovalEngine(db_path=":memory:"),
    audit_trail=AuditLogger(db_path=":memory:"),
)

def mock_shell_tool(command: str) -> str:
    """Mock AutoGen tool."""
    return "Executed"

safe_shell = CapFenceAutoGenTool(
    tool=mock_shell_tool,
    name="shell",
    agent_id="autogen-agent",
    risk_category="critical",
    gate=runtime,
)

print("Attempting to run a dangerous command...")
try:
    safe_shell("exec rm -rf /")
except AgentActionBlocked as e:
    print(f"BLOCKED: {e.detail}")
