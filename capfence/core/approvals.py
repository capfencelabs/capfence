"""Human Approval Workflows and Pre-Authorizations.

Allows autonomous systems to verify active approvals, including time-bound,
session-bound, Slack/GitHub-sourced, and environment-aware pre-approvals.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from capfence.core.capabilities import Capability
from capfence.core.db import SQLiteDBEngine


@dataclass
class ApprovalRequest:
    """Represents an active interactive request for human-in-the-loop approval."""

    id: str
    agent_id: str
    tool_name: str
    capability: str | None
    payload: dict[str, Any]
    reason: str
    status: str  # "pending", "approved", "rejected", "expired"
    created_at: float
    expires_at: float | None
    resolved_at: float | None = None
    resolved_by: str | None = None


@dataclass
class ApprovedGrant:
    """Represents a pre-approved operational credential/capability rule."""

    id: str
    actor: str
    capability: str          # resource.action.scope format
    environment: str         # e.g., "production" or "*"
    granted_by: str          # "slack", "github", "ops_admin", etc.
    created_at: float
    expires_at: float | None # for temporary approvals
    session_id: str | None   # for session-based approvals
    metadata: dict[str, Any] = field(default_factory=dict)


class ApprovalManager:
    """Approval Engine governing real-time interactive requests and pre-authorized capability grants."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db = SQLiteDBEngine(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        # Table for interactive requests
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                capability TEXT,
                payload TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL,
                resolved_at REAL,
                resolved_by TEXT
            )
            """
        )
        # Table for scoped pre-authorizations/grants
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS approved_grants (
                id TEXT PRIMARY KEY,
                actor TEXT NOT NULL,
                capability TEXT NOT NULL,
                environment TEXT NOT NULL,
                granted_by TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL,
                session_id TEXT,
                metadata TEXT NOT NULL
            )
            """
        )

    # =====================================================================
    # Pre-authorization and Scoped Grants API (New Core Feature)
    # =====================================================================

    def grant_temporary_approval(
        self,
        actor: str,
        capability: str,
        environment: str,
        duration_seconds: float,
        granted_by: str = "ops_admin",
        metadata: dict[str, Any] | None = None,
    ) -> ApprovedGrant:
        """Grant a temporary (time-bound expiring) capability to an actor."""
        now = time.time()
        expires_at = now + duration_seconds
        return self._insert_grant(actor, capability, environment, expires_at, None, granted_by, metadata)

    def grant_session_approval(
        self,
        actor: str,
        capability: str,
        environment: str,
        session_id: str,
        granted_by: str = "ops_admin",
        metadata: dict[str, Any] | None = None,
    ) -> ApprovedGrant:
        """Grant a session-bound capability to an actor."""
        return self._insert_grant(actor, capability, environment, None, session_id, granted_by, metadata)

    def _insert_grant(
        self,
        actor: str,
        capability: str,
        environment: str,
        expires_at: float | None,
        session_id: str | None,
        granted_by: str,
        metadata: dict[str, Any] | None,
    ) -> ApprovedGrant:
        grant_id = str(uuid.uuid4())
        now = time.time()
        meta = metadata or {}

        grant = ApprovedGrant(
            id=grant_id,
            actor=actor,
            capability=capability,
            environment=environment,
            granted_by=granted_by,
            created_at=now,
            expires_at=expires_at,
            session_id=session_id,
            metadata=meta,
        )

        self._db.execute(
            """
            INSERT INTO approved_grants
            (id, actor, capability, environment, granted_by, created_at, expires_at, session_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                grant.id,
                grant.actor,
                grant.capability,
                grant.environment,
                grant.granted_by,
                grant.created_at,
                grant.expires_at,
                grant.session_id,
                json.dumps(grant.metadata),
            ),
        )
        return grant

    def check_approval(
        self,
        actor: str,
        capability_str: str,
        environment: str,
        session_id: str | None = None,
    ) -> tuple[bool, ApprovedGrant | None]:
        """Check if an actor has an active approved grant matching the required capability.

        Integrates environment checks, expiration timers, and session matching.
        """
        required = Capability.parse(capability_str)
        now = time.time()

        rows = self._db.query(
            "SELECT id, actor, capability, environment, granted_by, created_at, expires_at, session_id, metadata "
            "FROM approved_grants WHERE actor = ? OR actor = '*'",
            (actor,),
        )

        for row in rows:
            grant = ApprovedGrant(
                id=row["id"],
                actor=row["actor"],
                capability=row["capability"],
                environment=row["environment"],
                granted_by=row["granted_by"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                session_id=row["session_id"],
                metadata=json.loads(row["metadata"]),
            )

            # 1. Verify capability match
            grant_cap = Capability.parse(grant.capability)
            if not grant_cap.matches(required):
                continue

            # 2. Verify environment match
            if grant.environment != "*" and grant.environment != environment:
                continue

            # 3. Verify expiration
            if grant.expires_at is not None and now > grant.expires_at:
                continue

            # 4. Verify session
            if grant.session_id is not None and grant.session_id != session_id:
                continue

            # Fully authorized grant!
            return True, grant

        return False, None

    # =====================================================================
    # Interactive Request approval workflows (Legacy Compatibility API)
    # =====================================================================

    def request_approval(
        self,
        agent_id: str,
        tool_name: str,
        capability: str | None,
        payload: dict[str, Any],
        reason: str,
        expires_in: float | None = 3600.0,
    ) -> ApprovalRequest:
        """Create a new pending approval request."""
        req_id = str(uuid.uuid4())
        now = time.time()
        expires_at = now + expires_in if expires_in else None

        req = ApprovalRequest(
            id=req_id,
            agent_id=agent_id,
            tool_name=tool_name,
            capability=capability,
            payload=payload,
            reason=reason,
            status="pending",
            created_at=now,
            expires_at=expires_at,
        )

        self._db.execute(
            """
            INSERT INTO approvals
            (id, agent_id, tool_name, capability, payload, reason, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                req.id,
                req.agent_id,
                req.tool_name,
                req.capability,
                json.dumps(req.payload),
                req.reason,
                req.status,
                req.created_at,
                req.expires_at,
            ),
        )
        return req

    def get_pending(self) -> list[ApprovalRequest]:
        """Get all pending approvals."""
        now = time.time()
        rows = self._db.query(
            "SELECT id, agent_id, tool_name, capability, payload, reason, status, created_at, expires_at "
            "FROM approvals WHERE status = 'pending'"
        )

        results = []
        for row in rows:
            req = ApprovalRequest(
                id=row["id"],
                agent_id=row["agent_id"],
                tool_name=row["tool_name"],
                capability=row["capability"],
                payload=json.loads(row["payload"]),
                reason=row["reason"],
                status=row["status"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
            )
            if req.expires_at and now > req.expires_at:
                self._update_status(req.id, "expired")
                req.status = "expired"
            else:
                results.append(req)
        return results

    def _update_status(self, req_id: str, status: str, resolved_by: str | None = None) -> None:
        now = time.time()
        self._db.execute(
            "UPDATE approvals SET status = ?, resolved_at = ?, resolved_by = ? WHERE id = ?",
            (status, now, resolved_by, req_id),
        )

    def approve(self, req_id: str, resolved_by: str | None = None) -> None:
        """Approve a request."""
        self._update_status(req_id, "approved", resolved_by)

    def reject(self, req_id: str, resolved_by: str | None = None) -> None:
        """Reject a request."""
        self._update_status(req_id, "rejected", resolved_by)

    def get_request(self, req_id: str) -> ApprovalRequest | None:
        rows = self._db.query(
            "SELECT id, agent_id, tool_name, capability, payload, reason, status, "
            "created_at, expires_at, resolved_at, resolved_by FROM approvals WHERE id = ?",
            (req_id,),
        )
        if not rows:
            return None
        row = rows[0]
        return ApprovalRequest(
            id=row["id"],
            agent_id=row["agent_id"],
            tool_name=row["tool_name"],
            capability=row["capability"],
            payload=json.loads(row["payload"]),
            reason=row["reason"],
            status=row["status"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            resolved_at=row["resolved_at"],
            resolved_by=row["resolved_by"],
        )

    def has_approved_request(self, agent_id: str, tool_name: str, payload: dict[str, Any]) -> bool:
        """Check if there is an approved request for this exact payload."""
        target_payload_str = json.dumps(payload, sort_keys=True)

        rows = self._db.query(
            "SELECT payload FROM approvals WHERE agent_id = ? AND tool_name = ? AND status = 'approved'",
            (agent_id, tool_name)
        )

        for row in rows:
            try:
                db_payload = json.loads(row["payload"])
                if json.dumps(db_payload, sort_keys=True) == target_payload_str:
                    return True
            except json.JSONDecodeError:
                continue

        return False


# Expose ApprovalEngine as alias to ApprovalManager
ApprovalEngine = ApprovalManager
