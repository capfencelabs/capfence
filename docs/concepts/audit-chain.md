# Audit Chain

CapFence records every enforcement decision in a tamper-evident audit log. The log is stored locally in SQLite and protected by a SHA-256 hash chain.

## What is a hash chain?

Each log entry contains:

- All decision fields (timestamp, agent ID, capability, decision, reason, payload hash)
- `prev_hash`: the hash of the previous entry
- `entry_hash`: the SHA-256 of all the above fields concatenated

```
entry_hash = SHA-256( canonical_json(entry_fields) + prev_hash )
```

This creates a chain: every entry is cryptographically linked to every entry before it. If any entry is modified, deleted, or reordered, all subsequent `entry_hash` values become invalid.

## Why this matters

A plain SQLite database can be edited by anyone with file access. The hash chain makes tampering **detectable**:

- Modify a past entry → its hash no longer matches what the next entry recorded
- Delete an entry → the chain breaks at that gap
- Add an entry out of order → the chain is inconsistent

You cannot silently alter the history.

## Verifying the chain

```bash
capfence verify --audit-log ./audit.db
✓ Audit chain intact. 1,284 entries verified.
```

If tampered:

```
✗ Chain broken at entry 847.
  Expected prev_hash: a3f2c1...
  Found prev_hash:    00000000...
```

## What gets logged

Every call to `gate.evaluate()` produces an audit entry regardless of the decision:

| Field | Description |
|---|---|
| `timestamp` | UTC time of evaluation |
| `agent_id` | Agent identifier |
| `capability` | Capability being requested |
| `decision` | `allow`, `deny`, or `require_approval` |
| `reason` | Why the decision was made |
| `payload_hash` | SHA-256 of the tool arguments |
| `risk_score` | Numeric risk score from the evaluator |
| `entry_hash` | Hash of this entry |
| `prev_hash` | Hash of the previous entry |

## Compliance relevance

| Regulation | Requirement addressed |
|---|---|
| EU AI Act Article 12 | Tamper-evident logs for high-risk AI systems |
| SOX 404 | Append-only decision logs for internal controls |
| GDPR | Audit trail of data access by automated systems |

## Limitations

The hash chain proves **integrity** (entries have not been altered), not **authenticity** (entries were created by CapFence). An attacker with file access can delete the entire database.

For authenticity guarantees, combine the audit log with:
- Optional Ed25519 signing of each entry when `capfence[crypto]` is installed
- Offline key storage
- Backup to immutable storage (S3 Object Lock, WORM tape)

## Related concepts

- [Replayability](replayability.md)
- [Audit log format reference](../reference/audit-log-format.md)
- [Replay an incident](../guides/replay-an-incident.md)
