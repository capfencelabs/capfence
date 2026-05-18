"""Capability System for autonomous AI systems.

Redesigned around resource.action.scope.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore

logger = logging.getLogger(__name__)


TAXONOMY_TO_CAPABILITY: dict[str, str] = {
    "balance_inquiry": "payment.balance.*",
    "transaction_history": "payment.history.*",
    "payment_initiation": "payment.transfer.*",
    "withdrawal": "payment.withdraw.*",
    "account_modification": "account.update.*",
    "compliance_check": "compliance.verify.*",
    "high_value_transfer": "payment.transfer.*",
    "stripe_payment_initiation": "payment.transfer.*",
    "stripe_refund": "payment.refund.*",
    "stripe_payout": "payment.transfer.*",
    "stripe_subscription": "payment.subscription.*",
    "stripe_issuing_card": "card.issue.*",
    "stripe_customer_mgmt": "account.update.*",
    "stripe_dispute": "stripe.dispute.*",
    "loan_origination": "loan.originate.*",
    "loan_modification": "loan.modify.*",
    "loan_disbursement": "loan.disburse.*",
    "credit_decision": "credit.decide.*",
    "account_closure": "account.close.*",
    "kyc_create": "kyc.create.*",
    "aml_flag": "compliance.aml_flag.*",
    "sanctions_screening": "compliance.sanctions_screening.*",
    "fx_conversion": "payment.fx_convert.*",
    "recurring_payment_setup": "payment.recurring_setup.*",
    "beneficiary_add": "account.beneficiary_add.*",
    "report_generate": "report.generate.*",
    "investment_order": "investment.order.*",
    "portfolio_rebalance": "investment.rebalance.*",
    "card_control": "card.control.*",
    "open_banking_consent": "open_banking.consent.*",
    "fee_override": "fee.override.*",
    "document_sign": "document.sign.*",
}


@dataclass(frozen=True)
class Capability:
    """Represents a capability in resource.action.scope format."""

    resource: str
    action: str
    scope: str

    @classmethod
    def parse(cls, cap_str: str) -> Capability:
        """Parse a capability string (e.g. 'github.push.main') into a Capability object."""
        if not cap_str or not isinstance(cap_str, str):
            raise ValueError("Capability string must be a non-empty string")
        
        # Alphanumeric, dot, underscore, hyphen, and wildcard only
        import re
        if not re.match(r"^[a-zA-Z0-9_\-\.\*]+$", cap_str):
            raise ValueError(f"Capability string contains invalid characters: '{cap_str}'")

        parts = cap_str.split(".", 2)
        if len(parts) == 1:
            return cls(resource=parts[0], action="*", scope="*")
        elif len(parts) == 2:
            return cls(resource=parts[0], action=parts[1], scope="*")
        else:
            return cls(resource=parts[0], action=parts[1], scope=parts[2])

    def __str__(self) -> str:
        return f"{self.resource}.{self.action}.{self.scope}"

    def matches(self, required: Capability) -> bool:
        """Check if this granted capability matches/covers the required capability.

        Supports wildcards ('*') in any position.
        """
        def match_part(granted: str, req: str) -> bool:
            return granted == "*" or granted == req

        return (
            match_part(self.resource, required.resource)
            and match_part(self.action, required.action)
            and match_part(self.scope, required.scope)
        )


class CapabilitySystem:
    """Policy engine verifying actor capabilities against minimal declarative policies."""

    def __init__(self) -> None:
        self.allowed: list[Capability] = []
        self.require_approval: list[Capability] = []
        self.denied: list[Capability] = []

    def load_policy(self, policy_data: dict[str, Any] | str | Path) -> None:
        """Load a simple declarative capability-based policy."""
        if isinstance(policy_data, (str, Path)):
            path = Path(policy_data)
            if not path.exists():
                raise FileNotFoundError(f"Policy file not found: {path}")
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        else:
            data = policy_data or {}

        # Handle simple capability arrays under allow, require_approval, deny
        for cap_str in data.get("allow", []):
            if isinstance(cap_str, str):
                self.allowed.append(Capability.parse(cap_str))
            elif isinstance(cap_str, dict) and "capability" in cap_str:
                self.allowed.append(Capability.parse(cap_str["capability"]))

        for cap_str in data.get("require_approval", []):
            if isinstance(cap_str, str):
                self.require_approval.append(Capability.parse(cap_str))
            elif isinstance(cap_str, dict) and "capability" in cap_str:
                self.require_approval.append(Capability.parse(cap_str["capability"]))

        for cap_str in data.get("deny", []):
            if isinstance(cap_str, str):
                self.denied.append(Capability.parse(cap_str))
            elif isinstance(cap_str, dict) and "capability" in cap_str:
                self.denied.append(Capability.parse(cap_str["capability"]))

        # For backwards compatibility with standard legacy rules
        for rule in data.get("rules", []):
            if isinstance(rule, dict) and "capability" in rule:
                cap = Capability.parse(rule["capability"])
                act = rule.get("action", "allow")
                if act == "deny" or act == "block":
                    self.denied.append(cap)
                elif act == "require_approval":
                    self.require_approval.append(cap)
                else:
                    self.allowed.append(cap)

    def evaluate_capability(self, required_cap_str: str) -> str:
        """Evaluate if a capability is allowed, denied, or requires approval."""
        required = Capability.parse(required_cap_str)

        # Deny always takes precedence (fail-closed)
        for cap in self.denied:
            if cap.matches(required):
                return "deny"

        # Require approval takes second precedence
        for cap in self.require_approval:
            if cap.matches(required):
                return "require_approval"

        # Allow rules
        for cap in self.allowed:
            if cap.matches(required):
                return "allow"

        return "default_deny"


# =====================================================================
# Backward Compatibility Layer
# =====================================================================

class CapabilityRegistry:
    """Registry for legacy capability definitions to prevent breaking existing code."""

    def __init__(self) -> None:
        self._capabilities: dict[str, dict[str, Any]] = {}
        self._groups: dict[str, list[str]] = {}

    def register(self, name: str, description: str = "", parent: str | None = None) -> None:
        """Register a new capability."""
        self._capabilities[name] = {"description": description, "parent": parent}

    def register_group(self, name: str, capabilities: list[str]) -> None:
        """Register a group of capabilities."""
        self._groups[name] = capabilities

    def resolve(self, capability: str) -> list[str]:
        """Resolve a capability or group into a list of specific capabilities."""
        if capability in self._groups:
            return self._groups[capability]
        return [capability]

    def get_parent(self, capability: str) -> str | None:
        """Get the parent of a capability."""
        cap = self._capabilities.get(capability)
        if cap:
            return cap.get("parent")
        return None

    def implies(self, granted_capability: str, required_capability: str) -> bool:
        """Check if granted capability implies the required capability."""
        if granted_capability == required_capability:
            return True

        if granted_capability.endswith(".*"):
            prefix = granted_capability[:-2]
            return required_capability.startswith(prefix)

        if granted_capability in self._groups:
            if required_capability in self._groups[granted_capability]:
                return True

        # Fallback to new Capability matches logic
        g = Capability.parse(granted_capability)
        r = Capability.parse(required_capability)
        return g.matches(r)


# Global default registry
default_registry = CapabilityRegistry()

# Standard legacy capabilities
default_registry.register("filesystem.read", "Read files from the filesystem")
default_registry.register("filesystem.write", "Write files to the filesystem")
default_registry.register("filesystem.delete", "Delete files from the filesystem")

default_registry.register("shell.execute", "Execute shell commands")
default_registry.register("shell.root_access", "Execute shell commands as root")

default_registry.register("database.read", "Read from database")
default_registry.register("database.write", "Write to database")
default_registry.register("database.drop", "Drop database tables")

default_registry.register("network.external_request", "Make external network requests")
default_registry.register("payments.transfer", "Transfer funds")
default_registry.register("mcp.tool.execute", "Execute an MCP tool")

# Groups
default_registry.register_group("filesystem.all", ["filesystem.read", "filesystem.write", "filesystem.delete"])
default_registry.register_group("database.all", ["database.read", "database.write", "database.drop"])
