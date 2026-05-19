"""Account management tools — destructive and sensitive operations.

Delete and bulk export tools are CRITICAL risk. Update is HIGH risk.
"""

from langchain.tools import BaseTool


class DeleteAccountTool(BaseTool):
    """Permanently delete a customer account and all associated data.

    Risk: CRITICAL — irreversible data destruction.
    Category: delete (delta=0.2)
    """
    name: str = "delete_account"
    description: str = "Permanently delete a customer account and all associated data. Requires admin confirmation."

    def _run(self, account_id: str, confirmation_code: str) -> str:
        return f"Account {account_id} permanently deleted (confirmation: {confirmation_code})"


class UpdateAccountTool(BaseTool):
    """Modify customer account details.

    Risk: HIGH — can change email, phone, billing address.
    Category: update (delta=0.3)
    """
    name: str = "update_account"
    description: str = "Update customer account information including email, phone, and billing address."

    def _run(self, account_id: str, field: str, value: str) -> str:
        return f"Updated {field} to '{value}' for account {account_id}"


class BulkDataExportTool(BaseTool):
    """Export all customer data in bulk.

    Risk: CRITICAL — mass data exfiltration vector.
    Category: data_export (delta=0.15)

    Must be wrapped by the agent before deployment.
    """
    name: str = "bulk_export"
    description: str = "Export all customer data to CSV/JSON. Includes PII, payment history, and account details."

    def _run(self, format: str = "csv", date_range: str | None = None) -> str:
        return f"Bulk data export initiated in {format} format for range: {date_range or 'all time'}"
