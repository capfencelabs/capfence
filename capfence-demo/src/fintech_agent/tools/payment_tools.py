"""Payment tools — money movement operations.

These are the highest-risk tools in the system. Every payment tool
MUST be wrapped with CapFenceTool before deployment.
"""

from langchain.tools import BaseTool


class PaymentTool(BaseTool):
    """Process customer payments via Stripe.

    Risk: HIGH — initiates real money movement.
    Category: payment_initiation (delta=0.3)
    """
    name: str = "process_payment"
    description: str = "Process a payment from a customer's saved payment method. Requires amount and customer_id."

    def _run(self, amount: float, customer_id: str, description: str = "") -> str:
        return f"Processed payment of ${amount:.2f} for customer {customer_id}: {description}"


class RefundTool(BaseTool):
    """Issue refunds to customers.

    Risk: HIGH — reverses payments, potential for abuse.
    Category: payment_initiation (delta=0.3)
    """
    name: str = "issue_refund"
    description: str = "Issue a refund for a previous transaction. Requires transaction_id and optional amount."

    def _run(self, transaction_id: str, amount: float | None = None, reason: str = "") -> str:
        refund_amount = f"${amount:.2f}" if amount else "full amount"
        return f"Refunded {refund_amount} for transaction {transaction_id}: {reason}"


class WireTransferTool(BaseTool):
    """Initiate wire transfers to external bank accounts.

    Risk: CRITICAL — irreversible external money movement.
    Category: payment_initiation (delta=0.3)

    Must be wrapped by the agent before deployment.
    """
    name: str = "wire_transfer"
    description: str = "Send a wire transfer to an external bank account. Requires routing_number, account_number, amount, and recipient_name."

    def _run(
        self,
        routing_number: str,
        account_number: str,
        amount: float,
        recipient_name: str,
        memo: str = "",
    ) -> str:
        return f"Wire transfer of ${amount:.2f} sent to {recipient_name} (acct: ...{account_number[-4:]})"
