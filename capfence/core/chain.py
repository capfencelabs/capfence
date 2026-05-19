"""Hash-chained audit log verifier.

Each audit entry is linked to the previous via SHA-256 hashes,
forming a tamper-evident chain. Changing any entry invalidates
all subsequent hashes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ChainEntry:
    """Immutable representation of a single chain link."""

    id: int
    agent_id: str
    task_context: str | None
    risk_category: str | None
    decision: str
    risk_score: float | None
    threshold: float | None
    payload_hash: str | None
    reason: str | None
    latency_ms: int | None
    timestamp: float
    prev_hash: str
    entry_hash: str
    actor: str | None = None
    action: str | None = None
    resource: str | None = None
    environment: str | None = None
    capability: str | None = None
    approval_state: str | None = None
    policy_decision: str | None = None
    execution_result: str | None = None
    metadata_json: str | None = None


def _canonical_json(data: dict[str, Any]) -> str:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_entry_hash(
    fields: dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute SHA-256 hash of entry fields + previous hash.

    Args:
        fields: Ordered dict of entry data (must not include entry_hash itself).
        prev_hash: Hash of previous entry (empty string for genesis).

    Returns:
        Hex digest of SHA-256.
    """
    payload = {**fields, "prev_hash": prev_hash}
    canonical = _canonical_json(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(entries: list[ChainEntry]) -> tuple[bool, list[str]]:
    """Verify integrity of a hash-chained audit log.

    Args:
        entries: List of chain entries in chronological order (oldest first).

    Returns:
        Tuple of (all_valid, list_of_error_messages).
    """
    errors: list[str] = []
    if not entries:
        return True, errors

    prev_hash = ""
    for i, entry in enumerate(entries):
        # 1. Check prev_hash linkage
        if entry.prev_hash != prev_hash:
            errors.append(
                f"Entry {entry.id} (index {i}): prev_hash mismatch. "
                f"Expected '{prev_hash[:16]}...', got '{entry.prev_hash[:16]}...'"
            )

        # 2. Recompute entry_hash and verify
        # Note: id is excluded because it is a DB artifact not known at record time
        fields: dict[str, Any] = {
            "agent_id": entry.agent_id,
            "task_context": entry.task_context,
            "risk_category": entry.risk_category,
            "decision": entry.decision,
            "risk_score": entry.risk_score,
            "threshold": entry.threshold,
            "payload_hash": entry.payload_hash,
            "reason": entry.reason,
            "latency_ms": entry.latency_ms,
            "timestamp": entry.timestamp,
        }
        extended_fields = {
            "actor": entry.actor,
            "action": entry.action,
            "resource": entry.resource,
            "environment": entry.environment,
            "capability": entry.capability,
            "approval_state": entry.approval_state,
            "policy_decision": entry.policy_decision,
            "execution_result": entry.execution_result,
            "metadata_json": entry.metadata_json,
        }
        if any(value is not None for value in extended_fields.values()):
            fields.update(extended_fields)
        expected = compute_entry_hash(fields, entry.prev_hash)
        if entry.entry_hash != expected:
            errors.append(
                f"Entry {entry.id} (index {i}): entry_hash mismatch. "
                f"Expected '{expected[:16]}...', got '{entry.entry_hash[:16]}...'"
            )

        prev_hash = entry.entry_hash

    return len(errors) == 0, errors


def verify_chain_from_rows(rows: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Convenience wrapper that converts raw DB rows to ChainEntry and verifies.

    Args:
        rows: List of dicts with keys matching ChainEntry fields.

    Returns:
        Tuple of (all_valid, list_of_error_messages).
    """
    errors: list[str] = []
    entries: list[ChainEntry] = []
    for i, row in enumerate(rows):
        missing = [k for k in ("id", "agent_id", "decision", "timestamp") if k not in row]
        if missing:
            errors.append(f"Row {i}: missing required keys {missing}")
            continue
        extended_protected = _uses_extended_hash_fields(row.get("metadata_json"))
        entries.append(
            ChainEntry(
                id=row["id"],
                agent_id=row["agent_id"],
                task_context=row.get("task_context"),
                risk_category=row.get("risk_category"),
                decision=row["decision"],
                risk_score=row.get("risk_score"),
                threshold=row.get("threshold"),
                payload_hash=row.get("payload_hash"),
                reason=row.get("reason"),
                latency_ms=row.get("latency_ms"),
                timestamp=row["timestamp"],
                prev_hash=row.get("prev_hash", ""),
                entry_hash=row.get("entry_hash", ""),
                actor=row.get("actor") if extended_protected else None,
                action=row.get("action") if extended_protected else None,
                resource=row.get("resource") if extended_protected else None,
                environment=row.get("environment") if extended_protected else None,
                capability=row.get("capability") if extended_protected else None,
                approval_state=row.get("approval_state") if extended_protected else None,
                policy_decision=row.get("policy_decision") if extended_protected else None,
                execution_result=row.get("execution_result") if extended_protected else None,
                metadata_json=row.get("metadata_json") if extended_protected else None,
            )
        )
    valid, verify_errors = verify_chain(entries)
    return valid and not errors, errors + verify_errors


def _uses_extended_hash_fields(metadata_json: Any) -> bool:
    """Return True for rows written with v0.8.2+ compact metadata hashing."""
    if not isinstance(metadata_json, str) or not metadata_json:
        return False
    try:
        parsed = json.loads(metadata_json)
    except json.JSONDecodeError:
        return False
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return metadata_json == canonical
