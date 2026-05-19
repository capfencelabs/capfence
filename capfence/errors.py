"""CapFence exception hierarchy.

All CapFence errors inherit from `CapFenceError`. Catch the base class to
handle any CapFence failure; catch specific subclasses for targeted handling.

    try:
        gate.evaluate(...)
    except AgentActionBlocked as e:
        # tool call blocked by the gate
        log.warning("blocked: %s", e.detail)
    except ConfigurationError:
        # bad gate mode, missing taxonomy, etc.
        raise
    except CapFenceError:
        # any other CapFence failure
        raise
"""

from __future__ import annotations

from typing import Any


class CapFenceError(Exception):
    """Base class for all CapFence errors."""


class ConfigurationError(CapFenceError, ValueError):
    """Invalid configuration (bad mode, empty bypass reason, malformed taxonomy).

    Inherits from ValueError for backward compatibility with code that catches
    ValueError on misconfiguration.
    """


class PolicyLoadError(ConfigurationError):
    """Raised when a policy file cannot be loaded or validated."""


class AgentActionBlocked(CapFenceError):
    """Raised when the gate blocks an agent tool call.

    Attributes:
        detail: Human-readable reason for the block.
        gate_result: The full GateResult (risk_score, threshold, metadata).
    """

    def __init__(self, detail: str, gate_result: Any | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.gate_result = gate_result


class AuditError(CapFenceError):
    """Raised when the audit log cannot be written or verified."""


class TaxonomyError(CapFenceError):
    """Raised when a taxonomy cannot be loaded or a category is invalid."""


class GatewayError(CapFenceError, RuntimeError):
    """Raised when the MCP gateway cannot proxy a request.

    Inherits from RuntimeError for backward compatibility.
    """
