"""Example: EU AI Act evidence report generation.

Uses the supported `capfence eu-ai-act` CLI command against the bundled demo.
"""

from __future__ import annotations

from pathlib import Path
from click.testing import CliRunner

from capfence.cli import main


def main_demo() -> None:
    output = Path("eu-ai-act-evidence.html")
    result = CliRunner().invoke(
        main,
        ["eu-ai-act", "capfence-demo/src", "--output", str(output)],
    )
    if result.exit_code != 0:
        raise RuntimeError(result.output)

    print("EU AI Act Evidence Report")
    print("=" * 50)
    print(result.output.strip())
    print(f"HTML: {output}")


if __name__ == "__main__":
    main_demo()
