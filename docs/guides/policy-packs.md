# Starter Policy Packs

Starter packs live under `policies/packs/`.

Each pack includes `baseline.yaml`, `strict.yaml`, and `permissive.yaml` variants:

- `shell`: shell and terminal execution.
- `filesystem-mcp`: filesystem access and MCP `tools/call` boundaries.
- `sql`: database and warehouse queries.
- `payments`: payment, refund, transfer, and invoice actions.
- `kubernetes`: Kubernetes, cloud, and Terraform operations.

Run the bundled fixtures:

```bash
capfence policy test tests/fixtures/policy-packs/starter_pack_cases.yaml
```

Explain one event:

```bash
capfence policy explain policies/packs/shell/baseline.yaml tests/fixtures/policy-packs/starter_pack_cases.yaml --json
```

Compare two variants against the same corpus:

```bash
capfence policy diff policies/packs/shell/strict.yaml policies/packs/shell/permissive.yaml tests/fixtures/policy-packs/starter_pack_cases.yaml
```

These packs are examples, not complete semantic parsers. Normalize payloads, resolve filesystem paths and symlinks before evaluation, parse SQL when practical, and keep downstream IAM or sandboxing in place.
