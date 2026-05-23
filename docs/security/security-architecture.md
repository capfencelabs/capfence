# Security Architecture

CapFence enforces policy at the tool boundary. If an agent can call the downstream tool directly with credentials outside CapFence, CapFence cannot protect that path.

## Trust boundaries

| Component | Trust assumption |
| --- | --- |
| Agent runtime | Untrusted decision maker; may be prompt-injected or mistaken. |
| CapFence adapter | Trusted normalization and enforcement point for a tool call. |
| Policy files | Trusted configuration; protect from unauthorized writes. |
| Approval store | Trusted for pending and resolved approval state. |
| Audit store | Local tamper-evident evidence store, not a remote immutable ledger. |
| Downstream tools | Trusted to execute only after CapFence authorizes the call. |
| Host environment | Trusted for local policy, audit, and signing-key integrity. |
| Secrets | Must not be exposed directly to agents outside gated tools. |

## Deployment modes

```text
In-process SDK:
Agent -> Adapter -> CapFence Runtime -> Tool
```

```text
MCP stdio proxy:
Agent Client -> CapFence MCP Gateway -> MCP Server -> Tool
```

```text
Gateway mode:
Agent Runtime -> CapFence Service -> Internal Tool/API
```

Gateway mode is an integration pattern, not a fully packaged hosted service in this repository.

## Bypass and failure model

| Case | Expected behavior | Mitigation |
| --- | --- | --- |
| Direct credential use outside CapFence | Not protected | Remove direct credentials from the agent runtime. |
| Ungated tool call | Not protected | Wrap every side-effecting tool and scan code in CI. |
| Malicious tool implementation | CapFence only authorizes the declared payload | Sandbox tools and use least-privilege identities. |
| Incomplete adapter normalization | Policy may evaluate the wrong fields | Test adapter payloads with fixtures. |
| Prompt injection mutates arguments | Policy evaluates final tool arguments | Deny or approve high-risk payload patterns. |
| Policy file tampering | Tampered policy may authorize unsafe actions | Protect policy files with repo review and deployment controls. |
| Audit store tampering | Hash-chain verification detects many local edits, but local deletion remains possible | Export audit evidence off-host. |
| Missing or malformed policy | Fail closed | Validate policies in CI before deploy. |
| Approval backend unavailable | Fail closed for approval-gated actions | Monitor approval availability. |
| Unknown capability | Fail closed | Add explicit allow or approval rules. |

## Audit and signing model

Hash chaining proves that a verified local audit sequence has not been silently edited in place. It does not prove that every event was recorded, that the host was uncompromised, or that deleted local evidence can be recovered.

For higher assurance:

- Export audit records to append-only storage outside the agent host.
- Store signing keys in a managed KMS or hardware-backed store.
- Rotate signing keys on a documented schedule.
- Preserve old public keys for verification.
- Treat gaps, corrupted entries, and failed verification as security events.
