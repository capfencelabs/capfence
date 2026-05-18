"""MCP gateway server — intercepts MCP tool calls through CapFence Gate.

Acts as a transparent proxy between an MCP client and MCP server.
Every tool/call request is evaluated by the Gate before forwarding.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
from typing import Any, cast

from capfence.core.runtime import ActionRuntime, ActionEvent, ExecutionVerdict
from capfence.errors import GatewayError

logger = logging.getLogger(__name__)

MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB


class MCPGatewayServer:
    """Transparent stdio proxy for MCP with CapFence gating.

    Intercepts JSON-RPC messages for tool calls and runs the payload
    through ActionRuntime before forwarding to the upstream server.
    """

    def __init__(
        self,
        upstream_command: list[str],
        gate: ActionRuntime | None = None,
        agent_id: str = "mcp-gateway",
        default_risk_category: str | None = None,
        policy_path: str | None = None,
        capability_map: dict[str, str] | None = None,
    ) -> None:
        self._upstream_command = upstream_command
        self._agent_id = agent_id
        self._default_risk_category = default_risk_category
        self._policy_path = policy_path
        self._capability_map = capability_map or {}
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

        if gate is None:
            if policy_path:
                self._gate = ActionRuntime.from_policy(policy_path)
            else:
                from capfence.core.capabilities import CapabilitySystem
                from capfence.core.approvals import ApprovalEngine
                from capfence.core.audit import AuditLogger
                self._gate = ActionRuntime(
                    capability_system=CapabilitySystem(),
                    approval_engine=ApprovalEngine(db_path=":memory:"),
                    audit_trail=AuditLogger(db_path=":memory:"),
                )
        else:
            self._gate = gate

    def _start_upstream(self) -> subprocess.Popen[str]:
        """Launch the upstream MCP server process."""
        logger.info("Starting upstream MCP server: %s", " ".join(self._upstream_command))
        return subprocess.Popen(
            self._upstream_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def _read_message(self, stream: Any) -> dict[str, Any] | None:
        """Read a JSON-RPC message from a stream (blocking)."""
        line = stream.readline()
        if not line:
            return None
        try:
            return cast(dict[str, Any], json.loads(line))
        except json.JSONDecodeError:
            logger.error("Failed to decode JSON-RPC message: %s", line)
            return None

    def _write_message(self, stream: Any, message: dict[str, Any]) -> None:
        """Write a JSON-RPC message to a stream (blocking)."""
        line = json.dumps(message) + "\n"
        stream.write(line)
        stream.flush()

    def _is_tool_call(self, message: dict[str, Any]) -> bool:
        """Check if message is a tools/call request."""
        method = message.get("method", "")
        return method in ("tools/call", "tool/call", "call_tool")

    def _extract_tool_payload(self, message: dict[str, Any]) -> dict[str, Any]:
        """Extract tool name and arguments from a tools/call request."""
        params = message.get("params", {})
        return {
            "tool_name": params.get("name", "unknown"),
            "arguments": params.get("arguments", {}),
        }

    def _build_blocked_response(self, request: dict[str, Any], verdict: ExecutionVerdict) -> dict[str, Any]:
        """Build a JSON-RPC error response for a blocked tool call."""
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {
                "code": -32000,
                "message": "CapFence blocked this tool call",
                "data": {
                    "reason": verdict.reason,
                    "risk_score": verdict.confidence,
                    "decision": verdict.decision,
                },
            },
        }

    def _forward_and_respond(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Forward request to upstream, return response."""
        with self._lock:
            if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
                logger.error("Upstream process not available")
                return None

            self._write_message(self._proc.stdin, request)
            return self._read_message(self._proc.stdout)

    def _handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single JSON-RPC message."""
        if not self._is_tool_call(message):
            # Non-tool call: forward transparently
            return self._forward_and_respond(message)

        # Tool call: evaluate through Gate
        payload = self._extract_tool_payload(message)
        tool_name = payload["tool_name"]
        arguments = payload["arguments"]

        # Determine risk category from tool name heuristics
        risk_category = self._default_risk_category
        if risk_category is None:
            risk_category = self._guess_category(tool_name)

        # Determine capability
        capability = self._capability_map.get(tool_name)
        if capability is None:
            capability = self._guess_capability(tool_name)

        parts = capability.split(".", 1)
        resource = parts[0]
        action = parts[1] if len(parts) > 1 else "execute"

        event = ActionEvent.create(
            actor=self._agent_id,
            action=action,
            resource=resource,
            environment="production",
            risk=risk_category or "medium",
            payload=arguments or {},
        )

        verdict = self._gate.execute(event)
        if not verdict.authorized:
            logger.warning(
                "Blocked MCP tool call: %s (decision=%s, reason=%s)",
                tool_name, verdict.decision, verdict.reason,
            )
            return self._build_blocked_response(message, verdict)

        # Allowed: forward to upstream
        return self._forward_and_respond(message)

    @staticmethod
    def _guess_category(tool_name: str) -> str | None:
        """Heuristic risk category from tool name."""
        name = tool_name.lower()
        if any(k in name for k in ("shell", "exec", "run", "command", "bash", "sh")):
            return "command_execution"
        if any(k in name for k in ("pay", "transfer", "send", "disburse", "stripe")):
            return "payment_initiation"
        if any(k in name for k in ("delete", "remove", "drop", "wipe")):
            return "delete"
        if any(k in name for k in ("write", "update", "modify", "patch")):
            return "write"
        if any(k in name for k in ("read", "get", "list", "view", "query")):
            return "read_only"
        return None

    @staticmethod
    def _guess_capability(tool_name: str) -> str | None:
        """Heuristic capability mapping from tool name."""
        name = tool_name.lower()
        if any(k in name for k in ("shell", "exec", "run", "command", "bash", "sh")):
            return "shell.execute"
        if any(k in name for k in ("pay", "transfer", "send", "disburse", "stripe")):
            return "payments.transfer"
        if any(k in name for k in ("delete", "remove", "drop", "wipe")):
            return "filesystem.delete"
        if any(k in name for k in ("write", "update", "modify", "patch")):
            return "filesystem.write"
        if any(k in name for k in ("read", "get", "list", "view", "query")):
            return "filesystem.read"
        return "mcp.tool.execute"

    def run(self) -> None:
        """Start the gateway and block on stdio proxying."""
        self._proc = self._start_upstream()
        if self._proc.stdout is None:
            raise GatewayError("Failed to start upstream process")

        # Thread to forward upstream stderr to our stderr for debugging
        def _drain_stderr() -> None:
            with self._lock:
                proc = self._proc
            if proc is None or proc.stderr is None:
                return
            for line in proc.stderr:
                logger.debug("[upstream stderr] %s", line.rstrip())

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        try:
            while True:
                message = self._read_message(sys.stdin)
                if message is None:
                    break

                response = self._handle_message(message)
                if response is not None:
                    self._write_message(sys.stdout, response)
        except KeyboardInterrupt:
            logger.info("Gateway shutting down (KeyboardInterrupt)")
        except (BrokenPipeError, OSError) as e:
            logger.info("Gateway shutting down (%s)", type(e).__name__)
        finally:
            with self._lock:
                if self._proc is not None:
                    self._proc.terminate()
                    try:
                        self._proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self._proc.kill()
