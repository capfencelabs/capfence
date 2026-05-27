# Policy Replay

Use `capfence replay` to inspect historical JSON/JSONL traces and to compare a
candidate policy against recorded events.

```bash
capfence replay trace.jsonl
capfence replay trace.jsonl --policy policies/candidate.yaml
```

For policy fixture development, prefer:

```bash
capfence policy test tests/fixtures/policy-packs/starter_pack_cases.yaml
capfence policy diff before.yaml after.yaml tests/fixtures/policy-packs/starter_pack_cases.yaml
```

Older internal notes referenced a `capfence simulate` command. That command is
not part of the current public CLI.
