# Production Trust Boundary Checklist

This checklist helps operators review whether a CapFence deployment is enforcing the trust boundary they expect before an agent can perform high-impact tool actions.

It is intentionally deployment-focused. CapFence provides deterministic gating, approval workflows, and tamper-evident audit logs, but the production boundary also depends on how credentials, wrappers, policies, and audit storage are configured around it.

## 1. Tool Calls Are Actually Wrapped

Confirm every high-impact tool call passes through a CapFence adapter or explicit `Gate.evaluate(...)` call before the downstream tool executes.

Review:

- payment, payout, account, database, shell, deployment, email, browser, and external API tools
- framework adapters in use, such as LangChain, OpenAI Agents, LangGraph, CrewAI, MCP, AutoGen, LlamaIndex, or PydanticAI
- custom internal tools that bypass framework wrappers

Evidence to keep:

- `capfence check ./src` output
- adapter configuration
- a sample blocked decision receipt

## 2. Raw Credentials Stay Behind the Gate

The agent should not hold raw downstream credentials that let it bypass CapFence.

Check that:

- API keys, OAuth tokens, SSH keys, wallet keys, and database credentials are only available to the wrapped executor or gateway layer
- the LLM-facing agent receives capabilities, not unrestricted secrets
- emergency break-glass credentials are outside the agent runtime

If the agent can directly call the downstream service with raw credentials, CapFence becomes advisory rather than an enforcement boundary.

## 3. Policies Cover Irreversible Actions

Review policy rules for actions that cannot be easily undone.

At minimum, decide whether these require `deny` or `require_approval`:

- money movement and payouts
- production database writes or schema changes
- public publishing or messaging
- account creation, deletion, suspension, or permission changes
- deployments and infrastructure mutations
- file deletion outside a sandbox
- access to private customer or regulated data

Avoid broad wildcard policies for production agents unless the scope, actor, environment, and duration are intentionally narrow.

## 4. Approval Flow Is Fail-Closed

For `require_approval` decisions, verify that the target tool is not invoked until approval is resolved.

Evidence to keep:

- pending approval request ID
- approving operator identity
- approval timestamp and scope
- resulting audit row
- proof that `tool_invoked=false` while approval was pending

Temporary grants should include actor, capability, environment, duration, and approving operator.

## 5. Audit Evidence Survives the Host

CapFence hash-chains local SQLite audit entries, which makes tampering detectable. Production evidence should also survive local host loss or file deletion.

For production, decide where audit evidence is exported or backed up:

- append-only object storage
- WORM or retention-locked storage
- signed evidence packs
- external log pipeline
- scheduled `capfence verify --audit-log ./audit.db` receipts

A valid local hash chain proves integrity of the available log. It does not by itself prove availability if the file can be deleted.

## 6. Replay and Fixture Tests Exist Before Enforcement

Before changing production policy, run fixture and replay checks against expected good and bad actions.

Keep evidence for:

- policy fixture results
- historical replay result
- expected false positives
- expected false negatives
- operator decision for ambiguous cases

## 7. Cross-Agent Inputs Are Treated As Untrusted

If one agent's output becomes another agent's tool input, preserve trust labels through the handoff or re-evaluate at the receiving boundary.

Check for:

- external user content converted into tool payloads
- autonomous agent-to-agent delegation
- MCP tool calls sourced from third-party outputs
- browser or document ingestion that later drives high-impact tools

## 8. Sample Decision Receipt

A useful production-readiness receipt should answer:

- actor: which agent or process requested the action?
- capability: what capability was requested?
- environment: local, staging, or production?
- decision: allow, deny, or require approval?
- tool invoked: true or false?
- approval ID: if required, which approval resolved it?
- audit hash: which hash-chain entry records the decision?
- verification: did `capfence verify` pass after the decision?

## Quick Readiness Summary

A deployment is closer to production-ready when:

- high-impact tools cannot execute outside CapFence
- raw downstream credentials are not exposed to the LLM-facing agent
- irreversible actions require approval or are denied
- approval-required actions are held fail-closed
- audit rows are hash-chained, verified, and exported somewhere durable
- policy changes are tested with fixtures or replay before enforcement
- cross-agent boundaries preserve trust context or re-check payloads
