"""Test runner for maintained core-concept examples.

Runs each example and reports success/failure.
Usage: python examples/run_all_examples.py
"""

import os
import subprocess
import sys
from pathlib import Path

EXAMPLES = [
    ("Hash Chain", "hash_chain_demo.py"),
    ("Ed25519 Signing", "ed25519_signing_demo.py"),
    ("OWASP Mapping", "owasp_report_demo.py"),
    ("LangGraph", "langgraph_demo.py"),
    ("EU AI Act", "eu_ai_act_demo.py"),
    ("Plaid Taxonomy", "plaid_taxonomy_demo.py"),
    ("Telemetry Metrics", "telemetry_demo.py"),
    ("Tamper Detection", "tamper_demo.py"),
]


def run_example(name: str, filename: str) -> bool:
    """Run a single example and return success status."""
    path = Path(__file__).parent / filename
    print(f"\n{'=' * 60}")
    print(f"Running: {name}")
    print(f"File:    {filename}")
    print("=" * 60)

    # Allow examples to import capfence from the repo root without pip install
    env = os.environ.copy()
    repo_root = str(Path(__file__).parent.parent.resolve())
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")

    result = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )

    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    success = result.returncode == 0
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"\n{status} (exit code: {result.returncode})")
    return success


def main():
    print("CapFence Core Example Test Runner")
    print(f"Python: {sys.version}")

    passed = 0
    failed = 0

    for name, filename in EXAMPLES:
        if run_example(name, filename):
            passed += 1
        else:
            failed += 1

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    print(f"Passed: {passed}/{len(EXAMPLES)}")
    print(f"Failed: {failed}/{len(EXAMPLES)}")

    if failed > 0:
        sys.exit(1)
    print("\nAll examples ran successfully!")


if __name__ == "__main__":
    main()
