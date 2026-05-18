"""Local immutable audit logging.

SQLite-backed append-only cryptographically linked log of all runtime decisions.
Supports CloudTrail-style autonomous execution records.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING


from capfence.core.chain import compute_entry_hash, verify_chain_from_rows
from capfence.core.keys import ensure_keypair, sign_entry
from capfence.core.db import SQLiteDBEngine

if TYPE_CHECKING:
    from capfence.core.runtime import ExecutionVerdict


class AuditLogger:
    """Append-only immutable audit trail with optional cryptographic signature chaining."""

    def __init__(self, db_path: str | Path = ":memory:", sign_entries: bool = False) -> None:
        self._db = SQLiteDBEngine(db_path)
        self._sign_entries = sign_entries
        self._keypair: tuple[str, str] | None = None
        if self._sign_entries:
            self._keypair = ensure_keypair()
        self._init_schema()
        self._migrate_legacy_entries()

    def _init_schema(self) -> None:
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                task_context TEXT,
                risk_category TEXT,
                decision TEXT NOT NULL,
                risk_score REAL,
                threshold REAL,
                payload_hash TEXT,
                reason TEXT,
                latency_ms INTEGER,
                timestamp REAL NOT NULL,
                prev_hash TEXT NOT NULL DEFAULT '',
                entry_hash TEXT NOT NULL DEFAULT '',
                signature TEXT,
                actor TEXT,
                action TEXT,
                resource TEXT,
                environment TEXT,
                capability TEXT,
                approval_state TEXT,
                policy_decision TEXT,
                execution_result TEXT,
                metadata_json TEXT
            )
            """
        )
        # Auto-migrate database schema on startup to append the premium new Action Runtime columns
        for col in [
            ("actor", "TEXT"),
            ("action", "TEXT"),
            ("resource", "TEXT"),
            ("environment", "TEXT"),
            ("capability", "TEXT"),
            ("approval_state", "TEXT"),
            ("policy_decision", "TEXT"),
            ("execution_result", "TEXT"),
            ("metadata_json", "TEXT"),
        ]:
            try:
                self._db.execute(f"ALTER TABLE audit_events ADD COLUMN {col[0]} {col[1]}")
            except Exception:
                pass  # Column already exists

    def _migrate_legacy_entries(self) -> None:
        """Backfill prev_hash and entry_hash for legacy rows that lack them."""
        legacy_rows = self._db.query("SELECT id FROM audit_events WHERE entry_hash = '' OR entry_hash IS NULL ORDER BY id ASC")
        legacy_ids = [row["id"] for row in legacy_rows]
        if not legacy_ids:
            return

        prev_hash = ""
        for entry_id in legacy_ids:
            row = self._db.query(
                "SELECT agent_id, task_context, risk_category, decision, risk_score, "
                "threshold, payload_hash, reason, latency_ms, timestamp "
                "FROM audit_events WHERE id = ?",
                (entry_id,),
            )
            if not row:
                continue
            r = row[0]
            timestamp = round(float(r["timestamp"]), 6)
            fields = {
                "agent_id": r["agent_id"],
                "task_context": r["task_context"],
                "risk_category": r["risk_category"],
                "decision": r["decision"],
                "risk_score": r["risk_score"],
                "threshold": r["threshold"],
                "payload_hash": r["payload_hash"],
                "reason": r["reason"],
                "latency_ms": r["latency_ms"],
                "timestamp": timestamp,
            }
            entry_hash = compute_entry_hash(fields, prev_hash)
            self._db.execute(
                "UPDATE audit_events SET prev_hash = ?, entry_hash = ? WHERE id = ?",
                (prev_hash, entry_hash, entry_id),
            )
            prev_hash = entry_hash



    def record_event(self, verdict: ExecutionVerdict) -> None:
        """Record an Action Runtime ExecutionVerdict with detailed CloudTrail schema metrics."""
        rows = self._db.query("SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1")
        prev_hash = rows[0]["entry_hash"] if rows else ""

        timestamp = round(verdict.timestamp, 6)
        decision_str = "pass" if verdict.authorized else "fail"

        fields = {
            "agent_id": verdict.event.actor,
            "task_context": verdict.event.action,
            "risk_category": str(verdict.event.risk),
            "decision": decision_str,
            "risk_score": float(verdict.event.risk) if isinstance(verdict.event.risk, (int, float)) else 0.0,
            "threshold": 0.0,
            "payload_hash": verdict.event.metadata.get("payload_hash") or "",
            "reason": verdict.reason,
            "latency_ms": verdict.metadata.get("latency_ms", 0),
            "timestamp": timestamp,
        }
        entry_hash = compute_entry_hash(fields, prev_hash)

        signature: str | None = None
        if self._sign_entries and self._keypair:
            sign_fields = {**fields, "prev_hash": prev_hash, "entry_hash": entry_hash}
            signature = sign_entry(sign_fields, self._keypair[1])

        self._db.execute(
            """
            INSERT INTO audit_events
            (agent_id, task_context, risk_category, decision, risk_score, threshold, payload_hash, reason, latency_ms, timestamp, prev_hash, entry_hash, signature,
             actor, action, resource, environment, capability, approval_state, policy_decision, execution_result, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verdict.event.actor,
                verdict.event.action,
                str(verdict.event.risk),
                decision_str,
                float(verdict.event.risk) if isinstance(verdict.event.risk, (int, float)) else 0.0,
                0.0,
                verdict.event.metadata.get("payload_hash") or "",
                verdict.reason,
                verdict.metadata.get("latency_ms", 0),
                timestamp,
                prev_hash,
                entry_hash,
                signature,
                verdict.event.actor,
                verdict.event.action,
                verdict.event.resource,
                verdict.event.environment,
                verdict.metadata.get("required_capability", ""),
                "approved" if verdict.authorized and verdict.approval_id else (
                    "pending" if verdict.decision == "require_approval" else "none"
                ),
                verdict.decision,
                "authorized" if verdict.authorized else "blocked",
                json.dumps(verdict.metadata),
            ),
        )

    def get_events(
        self,
        agent_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Fetch audit trail events."""
        if agent_id:
            return self._db.query(
                "SELECT * FROM audit_events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (agent_id, limit, offset),
            )
        else:
            return self._db.query(
                "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )

    def get_events_chronological(
        self,
        agent_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return events in chronological order (oldest first) for chain verification."""
        if agent_id:
            return self._db.query(
                "SELECT * FROM audit_events WHERE agent_id = ? ORDER BY timestamp ASC, id ASC LIMIT ? OFFSET ?",
                (agent_id, limit, offset),
            )
        else:
            return self._db.query(
                "SELECT * FROM audit_events ORDER BY timestamp ASC, id ASC LIMIT ? OFFSET ?",
                (limit, offset),
            )

    def verify(self) -> tuple[bool, list[str]]:
        """Verify hash-chain integrity of the entire audit log."""
        rows = self.get_events_chronological(limit=1000000)
        return verify_chain_from_rows(rows)


# Alias ImmutableAuditTrail as AuditLogger
ImmutableAuditTrail = AuditLogger
