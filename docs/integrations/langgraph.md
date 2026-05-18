# LangGraph Integration

CapFence integrates with LangGraph by wrapping tools before they are passed to graph nodes. Enforcement applies at every tool invocation, including within loops and conditional branches.

## Installation

```bash
pip install "capfence[langchain]"
```

## Wrapping tools for a graph

```python
from capfence import CapFenceTool
from langchain.tools import ShellTool
from langgraph.prebuilt import create_react_agent

safe_shell = CapFenceTool(
    tool=ShellTool(),
    agent_id="graph-agent",
    capability="shell.execute",
    policy_path="policies/shell.yaml"
)

# Pass wrapped tools to the graph agent
graph = create_react_agent(model, tools=[safe_shell])
```

## Manual graph nodes

When defining graph nodes manually, gate tool calls within the node function:

```python
from capfence import ActionRuntime, ActionEvent
from langgraph.graph import StateGraph

runtime = ActionRuntime.from_policy("policies/shell.yaml")

def tool_node(state):
    command = state["command"]
    
    # Formulate the governed event
    event = ActionEvent.create(
        actor="graph-agent",
        action="execute",
        resource="shell",
        environment="production",
        payload={"command": command}
    )
    
    verdict = runtime.execute(event)
    if not verdict.authorized:
        return {"error": f"Blocked: {verdict.reason}"}
        
    # execute tool
    output = run_shell(command)
    return {"output": output}

builder = StateGraph(MyState)
builder.add_node("tool", tool_node)
```

## Multi-agent graphs

In graphs where one agent hands off to another, propagate the agent lineage:

```python
event = ActionEvent.create(
    actor="executor-agent",
    action="write",
    resource="database",
    environment="production",
    payload={"query": sql}
)
verdict = runtime.execute(event)
```

## Related integrations

- [LangChain](langchain.md)
- [Custom frameworks](custom-frameworks.md)
