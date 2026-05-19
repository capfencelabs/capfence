"""Minimal AutoGen Integration Demo."""
from capfence import ActionEvent, ActionRuntime, ApprovalEngine, AuditLogger, CapabilitySystem

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

# In a real AutoGen setup, you would use wrap_tool
# For this demo, we simulate direct gating:
print("Attempting to run a dangerous command...")
event = ActionEvent.create(
    actor="autogen-agent",
    action="execute",
    resource="shell",
    risk="critical",
    payload={"command": "exec rm -rf /"},
)
result = runtime.execute(event)

if not result.authorized:
    print(f"BLOCKED: {result.reason}")
