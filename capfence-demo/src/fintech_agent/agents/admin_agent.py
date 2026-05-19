"""Admin agent — handles account management and data operations."""

from capfence.framework.langchain import CapFenceTool

from fintech_agent.tools.account_tools import DeleteAccountTool, UpdateAccountTool, BulkDataExportTool
from fintech_agent.tools.readonly_tools import BalanceInquiryTool, TransactionHistoryTool


def build_admin_agent():
    """Build the admin agent with gated tools.

    Returns a dict of tool_name -> tool_instance.
    """
    safe_delete = CapFenceTool(
        tool=DeleteAccountTool(),
        agent_id="admin-agent-1",
        risk_category="delete",
    )

    safe_update = CapFenceTool(
        tool=UpdateAccountTool(),
        agent_id="admin-agent-1",
        risk_category="update",
    )

    safe_balance = CapFenceTool(
        tool=BalanceInquiryTool(),
        agent_id="admin-agent-1",
        risk_category="read_only",
    )

    safe_history = CapFenceTool(
        tool=TransactionHistoryTool(),
        agent_id="admin-agent-1",
        risk_category="read_only",
    )

    safe_bulk_export = CapFenceTool(
        tool=BulkDataExportTool(),
        agent_id="admin-agent-1",
        risk_category="data_export",
    )

    return {
        "delete_account": safe_delete,
        "update_account": safe_update,
        "check_balance": safe_balance,
        "transaction_history": safe_history,
        "bulk_export": safe_bulk_export,
    }
