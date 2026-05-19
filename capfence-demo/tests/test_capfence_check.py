"""Test that CapFence correctly detects gated tools.

Run with: capfence check src/ --strict
"""

import subprocess
import sys
from pathlib import Path


def test_capfence_check_finds_all_tools():
    """Verify capfence check detects all 8 tools in the project."""
    src_dir = Path(__file__).parent.parent / "src"
    result = subprocess.run(
        [sys.executable, "-m", "capfence.cli", "check", str(src_dir)],
        capture_output=True,
        text=True,
    )
    output = result.stdout

    # All 8 tools should be found
    assert "8 tool(s) found" in output, f"Expected 8 tools, got:\n{output}"

    # All tools should be gated
    assert "Gated:           8" in output, f"Expected 8 gated, got:\n{output}"

    assert "Ungated:         0" in output, f"Expected 0 ungated, got:\n{output}"


def test_capfence_check_fail_on_ungated_passes_when_all_gated():
    """Verify --fail-on-ungated exits cleanly when all tools are gated."""
    src_dir = Path(__file__).parent.parent / "src"
    result = subprocess.run(
        [sys.executable, "-m", "capfence.cli", "check", str(src_dir), "--fail-on-ungated"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"Expected exit code 0 for gated tools, got {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_capfence_check_cross_file_detection():
    """Verify cross-file wrapper detection works.

    Tools are defined in fintech_agent/tools/*.py
    Wrappers are in fintech_agent/agents/*.py

    The scanner must connect these across files.
    """
    src_dir = Path(__file__).parent.parent / "src"
    result = subprocess.run(
        [sys.executable, "-m", "capfence.cli", "check", str(src_dir)],
        capture_output=True,
        text=True,
    )
    output = result.stdout

    # These tools are wrapped in agents/*.py — cross-file detection must work
    assert "PaymentTool" in output and "YES" in output, "PaymentTool should be gated"
    assert "RefundTool" in output and "YES" in output, "RefundTool should be gated"
    assert "WireTransferTool" in output and "YES" in output, "WireTransferTool should be gated"
    assert "DeleteAccountTool" in output and "YES" in output, "DeleteAccountTool should be gated"
    assert "UpdateAccountTool" in output and "YES" in output, "UpdateAccountTool should be gated"
    assert "BulkDataExportTool" in output and "YES" in output, "BulkDataExportTool should be gated"
    assert "BalanceInquiryTool" in output and "YES" in output, "BalanceInquiryTool should be gated"
    assert "TransactionHistoryTool" in output and "YES" in output, "TransactionHistoryTool should be gated"
