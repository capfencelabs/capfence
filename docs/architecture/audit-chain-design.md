# Audit Chain Design

The audit chain makes runtime decision logs tamper-evident.

## Storage model

CapFence stores audit events in SQLite. Each row contains decision metadata and cryptographic linkage to the previous row.

Core fields include:

- `agent_id`
- `task_context`
- `risk_category`
- `decision`
- `risk_score`
- `threshold`
- `payload_hash`
- `reason`
- `timestamp`
- `prev_hash`
- `entry_hash`
- `signature`

## Hash chaining

Each entry hash is computed from canonicalized decision fields plus the previous entry hash.

```text
entry_hash = SHA-256(canonical_event_fields + prev_hash)
```

Changing an old row changes its hash. Because the next row stores the previous hash, tampering breaks the chain.

## Signing

When signing is enabled, entries can be signed with Ed25519 if `capfence[crypto]` is installed. Hash chaining detects mutation; signatures help prove the entry was produced by a holder of the signing key. Without the optional crypto dependency, CapFence uses a compatibility fallback for local testing only.

## Verification

```bash
capfence verify --audit-log audit.db
```

Verification recomputes hashes and checks the chain from the first entry to the latest entry.
