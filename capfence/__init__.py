"""CAPFENCE — Trusted execution infrastructure for autonomous AI systems.

Deterministic fail-safe governance, approvals, capability policies,
and immutable cryptographic audit logging for high-risk operations.
"""

from __future__ import annotations

__version__ = "0.7.0"

# First-class Premium Redesign Primitives
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
from capfence.core.fsm import FSMOutcome, FailClosedFSM
from capfence.core.state import AgentStateStore
from capfence.core.taxonomy import TaxonomyLoader, stripe_mapper
from capfence.core.hash import compute_payload_hash
from capfence.core.chain import verify_chain, verify_chain_from_rows, ChainEntry
from capfence.core.keys import generate_keypair, load_keypair, ensure_keypair, sign_entry, verify_entry
from capfence.core.scorer import BaseScorer, KeywordScorer, RegexASTScorer, AdaptiveScorer, load_scorer
from capfence.cloud.client import CloudClient
from capfence.check import scan_directory, scan_file, ToolFinding
from capfence.assessment.scanner import scan_assessment, AssessmentData, ToolAssessment
from capfence.assessment.reporter import generate_html_report
from capfence.assessment.simulator import TraceSimulator
from capfence.assessment.builder import TaxonomyBuilder
from capfence.assessment.owasp import get_coverage_matrix, get_coverage_summary, generate_owasp_context
from capfence.assessment.eu_ai_act import generate_evidence_pack, EvidencePack
from capfence.framework.langchain import CapFenceTool
from capfence.framework.crewai import CapFenceCrewAITool
from capfence.framework.langgraph import CapFenceToolNode
from capfence.framework.openai_agents import CapFenceOpenAITool
from capfence.framework.pydanticai import CapFencePydanticTool
from capfence.framework.llamaindex import CapFenceLlamaIndexTool
from capfence.framework.autogen import CapFenceAutoGenTool
from capfence.mcp.gateway import MCPGatewayServer
from capfence.mcp.adapter import CapFenceMCPSession
from capfence.telemetry.client import TelemetryClient
from capfence.flow.tracer import FlowTracer, FlowEdge, TrustLevel

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
    "FSMOutcome",
    "FailClosedFSM",
    "AgentStateStore",
    "TaxonomyLoader",
    "stripe_mapper",
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
    "CloudClient",
    "scan_directory",
    "scan_file",
    "ToolFinding",
    "scan_assessment",
    "AssessmentData",
    "ToolAssessment",
    "generate_html_report",
    "TraceSimulator",
    "TaxonomyBuilder",
    "get_coverage_matrix",
    "get_coverage_summary",
    "generate_owasp_context",
    "generate_evidence_pack",
    "EvidencePack",
    "CapFenceTool",
    "CapFenceCrewAITool",
    "CapFenceToolNode",
    "CapFenceOpenAITool",
    "CapFencePydanticTool",
    "CapFenceLlamaIndexTool",
    "CapFenceAutoGenTool",
    "MCPGatewayServer",
    "CapFenceMCPSession",
    "TelemetryClient",
    "FlowTracer",
    "FlowEdge",
    "TrustLevel",
    "GATE_MODE_ENFORCE",
    "GATE_MODE_OBSERVE",
]
