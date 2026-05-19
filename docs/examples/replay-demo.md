# Replay Demo

Replay lets you reproduce agent tool decisions after the fact. This is useful for incident response, policy changes, and governance reviews.

## Trace file

Create a JSONL trace of tool calls:

```jsonl
{"call_id":"1","tool_name":"read_invoice","risk_category":"read_only","payload":{"path":"/data/invoices/123.json"}}
{"call_id":"2","tool_name":"transfer","risk_category":"payment_initiation","payload":{"amount":5000,"currency":"USD"}}
{"call_id":"3","tool_name":"shell","risk_category":"command_execution","payload":{"command":"rm -rf /var/lib/postgresql"}}
```

## Replay

```bash
capfence replay trace.jsonl
```

To replay against a candidate policy:

```bash
capfence replay trace.jsonl --policy policies/candidate.yaml
```

## What to look for

Replay answers questions such as:

- Which policy rule matched?
- Was the action allowed, denied, or sent for approval?
- Would a new policy have changed the outcome?
- Can the decision be explained without calling an LLM?

## Incident response pattern

1. Export the relevant trace or audit events.
2. Replay the action sequence against the policy used at the time.
3. Compare against a proposed policy update.
4. Verify the audit log chain to detect tampering.
