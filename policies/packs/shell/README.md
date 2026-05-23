# Shell Policy Pack

Use this pack for `shell.exec`, `process.spawn`, and terminal-like tool calls.

Variants:

- `baseline.yaml`: blocks destructive commands, requires approval for network or privilege-sensitive commands, and allows read-only diagnostics.
- `strict.yaml`: production-oriented; most network, package, Kubernetes, and Terraform commands require approval.
- `permissive.yaml`: local developer default; blocks destructive patterns and allows routine commands.

Limitations: these examples use string and regex matching, not full shell parsing. Normalize tool payloads before evaluation and prefer structured command metadata when available.
