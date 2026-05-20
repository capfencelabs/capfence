# Operational Pattern 03: MCP Filesystem Boundary

## 1. Executive Summary

### The Challenge
The Model Context Protocol (MCP) is the emerging standard for connecting client-side IDE agents (such as Claude Desktop, Cursor, or staging terminals) to local micro-tools (filesystem scanners, databases, and memory hubs). By design, **MCP servers trust the client entirely**.
If an agent downloads or interacts with an untrusted project codebase containing an adversarial prompt injection, the agent can be manipulated to:
1. **Steal Sensitive Credentials**: Access `~/.ssh/id_rsa`, `~/.aws/credentials`, or local environment `.env` files.
2. **Inject Backdoors**: Silently modify `package.json` scripts, inject malicious cronjobs, or tamper with system binaries.
3. **Execute Host Traversal**: Escape sandbox environments and write files directly to operating system root folders.

### The CapFence Pattern
CapFence can run as an stdio JSON-RPC proxy gateway between an MCP client and an upstream MCP server. The gateway parses tool calls, maps arguments to capability context, evaluates policy, and only forwards allowed requests.

---

## 2. Declarative Policy (`policies/mcp_policy.yaml`)

```yaml
# policies/mcp_policy.yaml
policy_name: MCP Host Sandboxing Policy
version: 1.0.0

deny:
  # Block access to system configurations
  - capability: filesystem.read
    path_prefix: "/etc"
  - capability: filesystem.read
    path_prefix: "/Users/anshumankumar/.ssh"
  # Block all shell execution attempts via MCP
  - capability: shell.execute

require_approval:
  # Escalates database mutations to admin
  - capability: database.write

allow:
  # Limit file tools to project workspace sandbox
  - capability: filesystem.read
    path_prefix: "/Users/anshumankumar/Documents/Capfence/capfence"
  - capability: filesystem.write
    path_prefix: "/Users/anshumankumar/Documents/Capfence/capfence"
```

---

## 3. Reference Implementation

Below is a self-contained Python program demonstrating stdio JSON-RPC interception, message payload extraction, capability mapping, and JSON-RPC error generation.

```python
import os
import json
from capfence import ActionRuntime, ActionEvent

def simulate_json_rpc_call(method: str, params: dict) -> str:
    """Mock JSON-RPC Client stream caller."""
    request = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": method,
        "params": params
    }
    return json.dumps(request)

def handle_incoming_mcp_request(raw_request_json: str, runtime: ActionRuntime) -> str:
    """Simulates the proxy interceptor inside MCPGatewayServer."""
    request = json.loads(raw_request_json)
    params = request.get("params", {})
    tool_name = params.get("name", "unknown")
    arguments = params.get("arguments", {})
    
    # 1. Map incoming MCP tool name to standard CapFence capabilities
    if "read" in tool_name or "view" in tool_name:
        resource, action = "filesystem", "read"
    elif "write" in tool_name or "save" in tool_name:
        resource, action = "filesystem", "write"
    else:
        resource, action = "shell", "execute"
        
    # 2. Build our governed event
    event = ActionEvent.create(
        actor="mcp-desktop-agent",
        action=action,
        resource=resource,
        environment="production",
        risk="medium",
        payload=arguments
    )
    
    # 3. Authorize via ActionRuntime
    verdict = runtime.execute(event)
    
    if verdict.authorized:
        print(f"✅ [MCP PROXY] Intercepted allowed tool '{tool_name}'. Forwarding to host server...")
        # Simulate normal host response
        return json.dumps({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"content": [{"type": "text", "text": "Successfully read file content."}]}
        })
    else:
        print(f"🛡️ [MCP PROXY] Intercepted BLOCKED tool '{tool_name}'. Injecting JSON-RPC protocol error...")
        # Return standard JSON-RPC custom error
        return json.dumps({
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {
                "code": -32000,
                "message": f"CapFence Security Violation: capability={resource}.{action} decision=denied reason={verdict.reason}",
                "data": {
                    "decision": verdict.decision,
                    "reason": verdict.reason
                }
            }
        })

def run_mcp_guard_demo():
    policy_path = "policies/mcp_policy.yaml"
    
    # Setup our sandbox policy file
    os.makedirs("policies", exist_ok=True)
    with open(policy_path, "w") as f:
        f.write("""
deny:
  - capability: filesystem.read
    path_prefix: "/etc"
  - capability: filesystem.read
    path_prefix: "/home/user/.ssh"
allow:
  - capability: filesystem.read
    path_prefix: "/Users/anshumankumar/Documents/Capfence/capfence"
""")

    runtime = ActionRuntime.from_policy(policy_path)
    print("🚀 MCP Boundary Guard Proxy initialized successfully.")

    # ----------------------------------------------------
    # Request 1: Safe File Read inside Project Directory
    # ----------------------------------------------------
    print("\n--- Scenario 1: Allowed Project File Read ---")
    req_safe = simulate_json_rpc_call(
        method="tools/call",
        params={
            "name": "read_file",
            "arguments": {"path": "/Users/anshumankumar/Documents/Capfence/capfence/pyproject.toml"}
        }
    )
    
    response_safe = handle_incoming_mcp_request(req_safe, runtime)
    print(f"Client Response Stream:\n{response_safe}")

    # ----------------------------------------------------
    # Request 2: Blocked File Read Outside Project (AWS Secrets)
    # ----------------------------------------------------
    print("\n--- Scenario 2: Blocked Directory Traversal Attempt ---")
    req_blocked = simulate_json_rpc_call(
        method="tools/call",
        params={
            "name": "read_file",
            "arguments": {"path": "/etc/passwd"}
        }
    )
    
    response_blocked = handle_incoming_mcp_request(req_blocked, runtime)
    print(f"Client Response Stream:\n{response_blocked}")

if __name__ == "__main__":
    run_mcp_guard_demo()
```

---

## 4. Operational Notes

### Proxy Security Profile
1. **Pre-upstream decision**: Blocked requests are not forwarded to the upstream MCP server.
2. **Workspace scope**: Filesystem access should be limited by explicit path policy and host-level permissions.
3. **Audit support**: Tool calls can be logged for replay and review.
4. **Limit**: The proxy does not replace sandboxing or least-privilege execution for the upstream MCP server.
