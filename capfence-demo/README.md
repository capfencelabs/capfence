# Fintech Agent Demo — CapFence Test Project

A realistic production-style fintech AI agent built with LangChain `BaseTool` subclasses. Designed to test CapFence's static analysis scanner (`capfence check`) against a real-world codebase.

## Architecture

```
src/fintech_agent/
├── tools/                    # Tool definitions (BaseTool subclasses)
│   ├── payment_tools.py      # PaymentTool, RefundTool, WireTransferTool
│   ├── account_tools.py      # DeleteAccountTool, UpdateAccountTool, BulkDataExportTool
│   └── readonly_tools.py     # BalanceInquiryTool, TransactionHistoryTool
└── agents/                   # Agent builders (wrap tools with CapFenceTool)
    ├── payment_agent.py      # Wraps all payment tools
    └── admin_agent.py        # Wraps all admin and read-only tools
```

## Tool Inventory

| Tool | Risk Category | Delta | Gated? | File |
|---|---|---|---|---|
| PaymentTool | payment_initiation | 0.3 | ✅ | tools/payment_tools.py |
| RefundTool | payment_initiation | 0.3 | ✅ | tools/payment_tools.py |
| WireTransferTool | payment_initiation | 0.3 | ✅ | tools/payment_tools.py |
| DeleteAccountTool | delete | 0.2 | ✅ | tools/account_tools.py |
| UpdateAccountTool | update | 0.3 | ✅ | tools/account_tools.py |
| BulkDataExportTool | data_export | 0.15 | ✅ | tools/account_tools.py |
| BalanceInquiryTool | read_only | 1.0 | ✅ | tools/readonly_tools.py |
| TransactionHistoryTool | read_only | 1.0 | ✅ | tools/readonly_tools.py |

**Key design decision**: Tools are defined in `tools/` and wrapped in `agents/` — this tests CapFence's cross-file wrapper detection.

## Testing CapFence

```bash
# Install
pip install capfence

# Scan the project
capfence check src/

# Expected output:
#   [SCAN] 8 tool(s) found
#   Gated: 8, Ungated: 0

# CI mode — fails if high-risk tools become ungated
capfence check src/ --fail-on-ungated
# Exit code: 0

# Generate machine-readable scanner output
capfence check src/ --report-json

# Run the verification tests
pip install -e ".[dev]"
pytest tests/ -v
```

## What This Demonstrates

1. **Cross-file detection** — tools in `tools/*.py`, wrappers in `agents/*.py`
2. **Complete gating** — every detected tool is wrapped before deployment
3. **CI integration** — `--fail-on-ungated` blocks regressions
4. **Risk categorization** — automatic delta assignment from tool names
5. **Framework detection** — LangChain BaseTool identified from imports
