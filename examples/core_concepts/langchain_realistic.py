"""Example: Realistic LangChain agent with BaseTool subclasses and CapFence wrappers.

This file uses actual BaseTool inheritance patterns (not mocks) so the
AST scanner can detect them via `capfence check`.

Usage:
    capfence check ./examples/langchain_realistic.py
    capfence check ./examples/langchain_realistic.py --report-json
"""

from langchain.tools import BaseTool

from capfence.framework.langchain import CapFenceTool


class ShellTool(BaseTool):
    """Run shell commands on the host system."""
    name: str = "shell"
    description: str = "Execute shell commands"

    def _run(self, command: str) -> str:
        return f"Executed: {command}"


class PaymentTool(BaseTool):
    """Process customer payments via Stripe."""
    name: str = "payment"
    description: str = "Process Stripe payments and transfers"

    def _run(self, amount: float, destination: str) -> str:
        return f"Paid ${amount} to {destination}"


class ReadBalanceTool(BaseTool):
    """Read account balance — read-only, safe."""
    name: str = "read_balance"
    description: str = "Read account balance information"

    def _run(self, account_id: str) -> str:
        return f"Balance for {account_id}: $1,000.00"


class DeleteAccountTool(BaseTool):
    """Permanently delete a customer account."""
    name: str = "delete_account"
    description: str = "Delete customer accounts from the system"

    def _run(self, account_id: str) -> str:
        return f"Deleted account: {account_id}"


class SendEmailTool(BaseTool):
    """Send emails via external API."""
    name: str = "send_email"
    description: str = "Send emails to customers via SendGrid"

    def _run(self, to_address: str, subject: str, body: str) -> str:
        return f"Sent email to {to_address}"


# These tools ARE wrapped with CapFenceTool — the scanner should detect this
safe_shell = CapFenceTool(
    tool=ShellTool(),
    agent_id="ops-agent-1",
    risk_category="execute",
)

safe_payment = CapFenceTool(
    tool=PaymentTool(),
    agent_id="finance-agent-1",
    risk_category="payment_initiation",
)

# Read-only tool wrapped for auditing
safe_balance = CapFenceTool(
    tool=ReadBalanceTool(),
    agent_id="finance-agent-1",
    risk_category="read_only",
)

# Delete tool wrapped
safe_delete = CapFenceTool(
    tool=DeleteAccountTool(),
    agent_id="ops-agent-1",
    risk_category="delete",
)

safe_email = CapFenceTool(
    tool=SendEmailTool(),
    agent_id="support-agent-1",
    risk_category="write",
)


def main():
    print("Realistic LangChain agent with 5 tools:")
    print("  - ShellTool (gated)")
    print("  - PaymentTool (gated)")
    print("  - ReadBalanceTool (gated)")
    print("  - DeleteAccountTool (gated)")
    print("  - SendEmailTool (gated)")


if __name__ == "__main__":
    main()
