"""Action Runtime for Autonomous AI Systems.

Builds a single, universal framework-agnostic execution model.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from capfence.core.capabilities import CapabilitySystem
from capfence.core.approvals import ApprovalEngine
from capfence.core.audit import AuditLogger  # Will be aliased/extended as ImmutableAuditTrail


@dataclass(frozen=True)
class ActionEvent:
    """Universal execution event model for autonomous operations."""

    actor: str               # The autonomous agent or caller ID
    action: str              # The operation name (e.g. 'push', 'execute', 'delete')
    resource: str            # The resource target (e.g. 'github.push.main', 'deployment')
    environment: str         # The environment context (e.g. 'production', 'development')
    risk: str | float        # Risk level (low, medium, high, critical) or risk score
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Validate non-empty fields
        if not self.actor or not isinstance(self.actor, str):
            raise ValueError("actor must be a non-empty string")
        if not self.action or not isinstance(self.action, str):
            raise ValueError("action must be a non-empty string")
        if not self.resource or not isinstance(self.resource, str):
            raise ValueError("resource must be a non-empty string")
        if not self.environment or not isinstance(self.environment, str):
            raise ValueError("environment must be a non-empty string")

        # Enforce strict risk domain
        if isinstance(self.risk, str):
            if self.risk.lower() not in {"low", "medium", "high", "critical"}:
                raise ValueError("risk string must be one of: 'low', 'medium', 'high', 'critical'")
        elif isinstance(self.risk, (int, float)):
            if not (0.0 <= float(self.risk) <= 1.0):
                raise ValueError("risk score must be a float between 0.0 and 1.0")
        else:
            raise ValueError("risk must be a string or a float")

        # Validate metadata JSON-serializability for absolute replay stability
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dictionary")
        for k, v in self.metadata.items():
            if not isinstance(k, str):
                raise ValueError("metadata keys must be strings")
        try:
            import json
            json.dumps(self.metadata)
        except (TypeError, OverflowError) as e:
            raise ValueError(f"metadata must be completely JSON-serializable for replay stability: {e}")

    @classmethod
    def create(
        cls,
        actor: str,
        action: str,
        resource: str,
        environment: str = "development",
        risk: str | float = "low",
        **metadata: Any,
    ) -> ActionEvent:
        """Helper to cleanly instantiate an ActionEvent with default arguments."""
        return cls(
            actor=actor,
            action=action,
            resource=resource,
            environment=environment,
            risk=risk,
            metadata=metadata,
        )


@dataclass(frozen=True)
class ExecutionVerdict:
    """The outcome of an Action Runtime evaluation check."""

    authorized: bool
    decision: str  # "allow", "deny", "require_approval"
    reason: str
    event: ActionEvent
    timestamp: float
    approval_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ActionRuntime:
    """Universal execution runtime for autonomous systems.

    Centralizes capability, environment, and approval enforcement deterministically.
    """

    def __init__(
        self,
        capability_system: CapabilitySystem,
        approval_engine: ApprovalEngine,
        audit_trail: AuditLogger,
        mode: str = "enforce",
    ) -> None:
        self.capability_system = capability_system
        self.approval_engine = approval_engine
        self.audit_trail = audit_trail
        self.mode = mode

    @classmethod
    def from_policy(cls, policy_path: str | Path, mode: str = "enforce") -> ActionRuntime:
        """Create a default ActionRuntime configured with a local policy file."""
        caps = CapabilitySystem()
        caps.load_policy(policy_path)
        return cls(
            capability_system=caps,
            approval_engine=ApprovalEngine(),
            audit_trail=AuditLogger(),
            mode=mode,
        )

    def execute(self, event: ActionEvent) -> ExecutionVerdict:
        """Safely evaluate and govern an ActionEvent, returning a deterministic ExecutionVerdict."""
        start_time = time.time()

        # 1. Format required capability in resource.action.scope format
        scope = event.metadata.get("scope") or event.environment or "*"
        required_cap_str = f"{event.resource}.{event.action}.{scope}"

        # 2. Check declarative capability policy
        policy_verdict = self.capability_system.evaluate_capability(required_cap_str)

        authorized = False
        decision = "deny"
        reason = "policy_default_deny"
        approval_id = None

        if policy_verdict == "allow":
            authorized = True
            decision = "allow"
            reason = "policy_allow"
        elif policy_verdict == "deny":
            authorized = False
            decision = "deny"
            reason = "policy_deny"
        elif policy_verdict == "require_approval" or event.metadata.get("require_approval", False):
            # Check approval engine for existing/active pre-approval grants (temporary or session)
            session_id = event.metadata.get("session_id")
            has_approval, grant = self.approval_engine.check_approval(
                actor=event.actor,
                capability_str=required_cap_str,
                environment=event.environment,
                session_id=session_id,
            )

            if has_approval and grant is not None:
                authorized = True
                decision = "allow"
                reason = f"approved_grant:{grant.id}:{grant.granted_by}"
                approval_id = grant.id
            else:
                # Check for active interactive manual approval request matches
                payload = event.metadata.get("payload") or event.metadata
                if self.approval_engine.has_approved_request(event.actor, event.action, payload):
                    authorized = True
                    decision = "allow"
                    reason = "previously_approved"
                else:
                    # Fail-closed but queue a pending interactive manual approval request
                    req = self.approval_engine.request_approval(
                        agent_id=event.actor,
                        tool_name=event.action,
                        capability=required_cap_str,
                        payload=payload,
                        reason=f"Action Runtime enforce: require_approval for {required_cap_str}",
                    )
                    authorized = False
                    decision = "require_approval"
                    reason = f"approval_required:{req.id}"
                    approval_id = req.id

        # 3. Observe mode bypass: always authorize, but log the true underlying verdict
        if self.mode == "observe":
            authorized = True
            reason = f"observed: would_have_blocked_due_to_{reason}"

        elapsed_ms = int((time.time() - start_time) * 1000)

        verdict = ExecutionVerdict(
            authorized=authorized,
            decision=decision,
            reason=reason,
            event=event,
            timestamp=start_time,
            approval_id=approval_id,
            metadata={
                "latency_ms": elapsed_ms,
                "required_capability": required_cap_str,
                "observe_mode": self.mode == "observe",
            },
        )

        # 4. Commit to immutable audit trail
        self.audit_trail.record_event(verdict)

        return verdict
