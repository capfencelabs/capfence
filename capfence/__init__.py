"""CAPFENCE — Trusted execution infrastructure for autonomous AI systems.

Deterministic fail-safe execution boundaries, approvals, capability policies,
and immutable audit logging for high-risk operations.
"""

from __future__ import annotations

__version__ = "0.7.1"

# Core Enforcement Primitives
from capfence.core.runtime import ActionEvent, ActionRuntime, ExecutionVerdict
from capfence.core.capabilities import Capability, CapabilitySystem, CapabilityRegistry
from capfence.core.approvals import ApprovedGrant, ApprovalEngine, ApprovalManager
from capfence.core.audit import ImmutableAuditTrail, AuditLogger
from capfence.core.replay import ReplayEngine, ReplaySummary, ReplayEventResult

# Legacy SDK Primitives and Adapters
from capfence.core.gate import Gate, GATE_MODE_ENFORCE, GATE_MODE_OBSERVE
from capfence.types import GateResult
from capfence.errors import (
    CapFenceError,
    AgentActionBlocked,
    ConfigurationError,
    PolicyLoadError,
    AuditError,
    TaxonomyError,
    GatewayError,
)

# Core Helper Primitives
from capfence.core.hash import compute_payload_hash
from capfence.core.chain import verify_chain, verify_chain_from_rows, ChainEntry
from capfence.core.keys import generate_keypair, load_keypair, ensure_keypair, sign_entry, verify_entry
from capfence.core.scorer import BaseScorer, KeywordScorer, RegexASTScorer, AdaptiveScorer, load_scorer

# Preferred Integrations
from capfence.framework.langchain import CapFenceTool
from capfence.framework.langgraph import CapFenceToolNode
from capfence.framework.openai_agents import CapFenceOpenAITool
from capfence.mcp.gateway import MCPGatewayServer
from capfence.mcp.adapter import CapFenceMCPSession

__all__ = [
    "__version__",
    # Core Primitives
    "ActionEvent",
    "ActionRuntime",
    "ExecutionVerdict",
    "Capability",
    "CapabilitySystem",
    "CapabilityRegistry",
    "ApprovedGrant",
    "ApprovalEngine",
    "ApprovalManager",
    "ImmutableAuditTrail",
    "AuditLogger",
    "ReplayEngine",
    "ReplaySummary",
    "ReplayEventResult",
    # Legacy Primitives
    "Gate",
    "GateResult",
    "CapFenceError",
    "AgentActionBlocked",
    "ConfigurationError",
    "PolicyLoadError",
    "AuditError",
    "TaxonomyError",
    "GatewayError",
    # Core Helpers
    "compute_payload_hash",
    "verify_chain",
    "verify_chain_from_rows",
    "ChainEntry",
    "generate_keypair",
    "load_keypair",
    "ensure_keypair",
    "sign_entry",
    "verify_entry",
    "BaseScorer",
    "KeywordScorer",
    "RegexASTScorer",
    "AdaptiveScorer",
    "load_scorer",
    # Integrations
    "CapFenceTool",
    "CapFenceToolNode",
    "CapFenceOpenAITool",
    "MCPGatewayServer",
    "CapFenceMCPSession",
    "GATE_MODE_ENFORCE",
    "GATE_MODE_OBSERVE",
]
