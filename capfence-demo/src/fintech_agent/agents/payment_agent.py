"""Payment agent — handles customer payments and refunds."""

from capfence.framework.langchain import CapFenceTool

from fintech_agent.tools.payment_tools import PaymentTool, RefundTool, WireTransferTool


def build_payment_agent():
    """Build the payment agent with gated tools.

    Returns a dict of tool_name -> tool_instance.
    """
    safe_payment = CapFenceTool(
        tool=PaymentTool(),
        agent_id="payment-agent-1",
        risk_category="payment_initiation",
    )

    safe_refund = CapFenceTool(
        tool=RefundTool(),
        agent_id="payment-agent-1",
        risk_category="payment_initiation",
    )

    safe_wire_transfer = CapFenceTool(
        tool=WireTransferTool(),
        agent_id="payment-agent-1",
        risk_category="payment_initiation",
    )

    return {
        "process_payment": safe_payment,
        "issue_refund": safe_refund,
        "wire_transfer": safe_wire_transfer,
    }
