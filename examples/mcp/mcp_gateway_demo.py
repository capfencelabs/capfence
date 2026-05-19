"""Minimal MCP Gateway Demo."""
from capfence import ActionRuntime, ApprovalEngine, AuditLogger, CapabilitySystem
from capfence.mcp.gateway import MCPGatewayServer

if __name__ == "__main__":
    print("Initializing MCP Gateway...")
    caps = CapabilitySystem()
    caps.load_policy({"allow": ["mcp.tool.execute"], "deny": [{"capability": "mcp.tool.execute", "tool_name": "admin_*"}]})
    gate = ActionRuntime(
        capability_system=caps,
        approval_engine=ApprovalEngine(db_path=":memory:"),
        audit_trail=AuditLogger(db_path=":memory:"),
    )
    gateway = MCPGatewayServer(
        upstream_command=["python", "-m", "mcp_server_filesystem", "/tmp"],
        gate=gate,
        agent_id="mcp-agent-1"
    )
    
    print("Gateway ready. Run with actual MCP client to see traffic intercepted.")
    # gateway.run() # Un-comment to run the actual blocking proxy
