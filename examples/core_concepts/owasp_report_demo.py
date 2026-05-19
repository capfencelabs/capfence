"""Example: OWASP Agentic Top 10 control mapping.

Prints a lightweight local mapping without requiring an external reporting
package.
"""


CONTROLS = [
    ("LLM01", "Prompt injection", "Runtime authorization before tool execution"),
    ("LLM02", "Insecure output handling", "Policy checks on generated commands and writes"),
    ("LLM06", "Excessive agency", "Capability-scoped allow/deny/approval rules"),
    ("LLM08", "Vector and embedding weakness", "Replay and audit evidence for incident review"),
    ("LLM10", "Unbounded consumption", "Approval and policy gates for high-risk operations"),
]


def main() -> None:
    print("OWASP Agentic AI Control Mapping")
    print("=" * 50)
    print(f"Mapped risks: {len(CONTROLS)}")
    print()
    print(f"{'ID':<8} {'Risk':<34} Control")
    print("-" * 90)
    for risk_id, risk_name, control in CONTROLS:
        print(f"{risk_id:<8} {risk_name:<34} {control}")


if __name__ == "__main__":
    main()
