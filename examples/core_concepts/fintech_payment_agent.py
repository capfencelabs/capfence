"""Realistic production-style fintech payment agent with CapFence gates.

Mirrors patterns from actual fintech production code:
  - Stripe SDK calls wrapped in retry + rate-limit logic
  - Async task queue simulation (Celery-style)
  - Idempotency keys on all mutations
  - Structured error handling with escalation
  - CapFence gates inserted at every money-movement boundary

This file is intentionally explicit and verbose — it shows WHERE and HOW
to integrate CapFence gates in realistic agent code.

Run:
    python examples/fintech_payment_agent.py

Requires: no API keys — all Stripe calls are stubbed.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from capfence import Gate, AuditLogger, GateResult
from capfence.core.state import AgentStateStore

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

# ── Audit log to a persistent file so you can run `capfence verify` on it ──
AUDIT_DB = Path("/tmp/capfence_fintech_demo.db")


# ── Shared gate: one instance per process, injected via DI in production ──────
def make_gate() -> Gate:
    state_store = AgentStateStore()
    audit_logger = AuditLogger(db_path=AUDIT_DB, sign_entries=False)
    return Gate(
        state_store=state_store,
        taxonomy_path="financial",
        audit_logger=audit_logger,
    )


GATE = make_gate()


# ─────────────────────────────────────────────────────────────────────────────
# Stubs — replace with real SDK calls in production
# ─────────────────────────────────────────────────────────────────────────────

class StripeError(Exception):
    """Stub for stripe.error.StripeError."""
    def __init__(self, message: str, code: str = "api_error") -> None:
        super().__init__(message)
        self.code = code


class RateLimitError(StripeError):
    def __init__(self) -> None:
        super().__init__("Too Many Requests", code="rate_limit")


def _stripe_charge_stub(
    amount: int,
    currency: str,
    customer: str,
    idempotency_key: str,
    description: str,
) -> dict[str, Any]:
    """Stub for stripe.PaymentIntent.create()."""
    logger.info("[stripe-stub] charge %s %s to %s (idem=%s)", amount, currency, customer, idempotency_key[:8])
    return {
        "id": f"pi_{uuid.uuid4().hex[:16]}",
        "amount": amount,
        "currency": currency,
        "customer": customer,
        "status": "succeeded",
        "description": description,
    }


def _stripe_refund_stub(charge_id: str, amount: int, idempotency_key: str) -> dict[str, Any]:
    """Stub for stripe.Refund.create()."""
    logger.info("[stripe-stub] refund %s on %s (idem=%s)", amount, charge_id, idempotency_key[:8])
    return {
        "id": f"re_{uuid.uuid4().hex[:16]}",
        "amount": amount,
        "charge": charge_id,
        "status": "succeeded",
    }


def _stripe_payout_stub(
    amount: int,
    currency: str,
    destination: str,
    idempotency_key: str,
) -> dict[str, Any]:
    """Stub for stripe.Payout.create()."""
    logger.info("[stripe-stub] payout %s %s → %s (idem=%s)", amount, currency, destination, idempotency_key[:8])
    return {
        "id": f"po_{uuid.uuid4().hex[:16]}",
        "amount": amount,
        "currency": currency,
        "destination": destination,
        "status": "paid",
        "arrival_date": int(time.time()) + 86400,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Retry decorator — production pattern for transient Stripe errors
# ─────────────────────────────────────────────────────────────────────────────

def _with_retry(fn: Any, max_attempts: int = 3, backoff_base: float = 0.5) -> Any:
    """Call fn with exponential backoff on rate-limit errors."""
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except RateLimitError:
            if attempt == max_attempts:
                raise
            wait = backoff_base * (2 ** (attempt - 1))
            logger.warning("[retry] rate limit hit, waiting %.1fs (attempt %d/%d)", wait, attempt, max_attempts)
            time.sleep(wait)
    return None  # unreachable


# ─────────────────────────────────────────────────────────────────────────────
# Domain types
# ─────────────────────────────────────────────────────────────────────────────

class PaymentStatus(str, Enum):
    PENDING = "pending"
    GATED = "gated"          # CapFence blocked execution
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"


@dataclass
class PaymentRecord:
    payment_id: str
    customer_id: str
    amount_cents: int
    currency: str
    description: str
    status: PaymentStatus = PaymentStatus.PENDING
    stripe_id: str | None = None
    gate_result: GateResult | None = None
    idempotency_key: str = field(default_factory=lambda: str(uuid.uuid4()))
    error: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Tool layer — each tool calls the gate BEFORE the Stripe API
# ─────────────────────────────────────────────────────────────────────────────

class PaymentTools:
    """Agent-callable tools for Stripe payment operations.

    CapFence gate is evaluated BEFORE each Stripe call.
    If the gate blocks, the payment is recorded with status=GATED
    and the Stripe call is never made.
    """

    def __init__(self, agent_id: str, gate: Gate = GATE) -> None:
        self._agent_id = agent_id
        self._gate = gate

    def charge_customer(
        self,
        customer_id: str,
        amount_cents: int,
        currency: str = "usd",
        description: str = "",
    ) -> PaymentRecord:
        """Charge a customer via Stripe PaymentIntent.

        Gate category: stripe_payment_initiation (delta=0.3).
        Blocked if risk_score > 0.3.
        """
        record = PaymentRecord(
            payment_id=str(uuid.uuid4()),
            customer_id=customer_id,
            amount_cents=amount_cents,
            currency=currency,
            description=description,
        )

        # ── Gate evaluation ───────────────────────────────────────────────────
        gate_result = self._gate.evaluate(
            agent_id=self._agent_id,
            task_context="charge_customer",
            risk_category="stripe_payment_initiation",
            payload={
                "customer_id": customer_id,
                "amount_cents": amount_cents,
                "currency": currency,
                "description": description,
            },
        )
        record.gate_result = gate_result
        # ─────────────────────────────────────────────────────────────────────

        if not gate_result.passed:
            record.status = PaymentStatus.GATED
            logger.warning(
                "[gate] charge_customer BLOCKED agent=%s amount=%d risk_score=%.3f threshold=%.3f",
                self._agent_id, amount_cents, gate_result.risk_score or 0, gate_result.threshold or 0,
            )
            return record

        try:
            result = _with_retry(
                lambda: _stripe_charge_stub(
                    amount=amount_cents,
                    currency=currency,
                    customer=customer_id,
                    idempotency_key=record.idempotency_key,
                    description=description,
                )
            )
            record.stripe_id = result["id"]
            record.status = PaymentStatus.SUCCEEDED
        except StripeError as e:
            record.status = PaymentStatus.FAILED
            record.error = str(e)
            logger.error("[stripe] charge failed: %s", e)

        return record

    def refund_payment(
        self,
        charge_id: str,
        amount_cents: int,
        reason: str = "requested_by_customer",
    ) -> dict[str, Any]:
        """Issue a partial or full refund.

        Gate category: stripe_refund (delta=0.4).
        Higher threshold than charge — refunds can be reversed more easily.
        """
        gate_result = self._gate.evaluate(
            agent_id=self._agent_id,
            task_context="refund_payment",
            risk_category="stripe_refund",
            payload={
                "charge_id": charge_id,
                "amount_cents": amount_cents,
                "reason": reason,
            },
        )

        if not gate_result.passed:
            logger.warning("[gate] refund_payment BLOCKED agent=%s charge=%s", self._agent_id, charge_id)
            return {"gated": True, "charge_id": charge_id, "gate_reason": gate_result.reason}

        idem_key = str(uuid.uuid4())
        try:
            result = _with_retry(
                lambda: _stripe_refund_stub(
                    charge_id=charge_id,
                    amount=amount_cents,
                    idempotency_key=idem_key,
                )
            )
            return result
        except StripeError as e:
            logger.error("[stripe] refund failed: %s", e)
            return {"error": str(e), "charge_id": charge_id}

    def payout_to_bank(
        self,
        amount_cents: int,
        destination_bank_account: str,
        currency: str = "usd",
    ) -> dict[str, Any]:
        """Move funds from Stripe balance to an external bank account.

        Gate category: stripe_payout (delta=0.2).
        Low threshold — payouts are irreversible on most payment rails.
        """
        gate_result = self._gate.evaluate(
            agent_id=self._agent_id,
            task_context="payout_to_bank",
            risk_category="stripe_payout",
            payload={
                "amount_cents": amount_cents,
                "destination": destination_bank_account,
                "currency": currency,
                "action": "create_payout",   # matches "create_payout", "payout"
                "disburse": True,            # matches "disburse"
            },
        )

        if not gate_result.passed:
            logger.warning(
                "[gate] payout_to_bank BLOCKED agent=%s amount=%d",
                self._agent_id, amount_cents,
            )
            return {"gated": True, "gate_reason": gate_result.reason, "amount_cents": amount_cents}

        idem_key = str(uuid.uuid4())
        try:
            result = _with_retry(
                lambda: _stripe_payout_stub(
                    amount=amount_cents,
                    currency=currency,
                    destination=destination_bank_account,
                    idempotency_key=idem_key,
                )
            )
            return result
        except StripeError as e:
            logger.error("[stripe] payout failed: %s", e)
            return {"error": str(e)}

    def high_value_wire(
        self,
        amount_cents: int,
        destination_account: str,
        swift_code: str,
        memo: str = "",
    ) -> dict[str, Any]:
        """Initiate a high-value wire transfer.

        Gate category: high_value_transfer (delta=0.15).
        Very low threshold — bulk/SWIFT wires require human-in-the-loop by policy.
        """
        gate_result = self._gate.evaluate(
            agent_id=self._agent_id,
            task_context="high_value_wire",
            risk_category="high_value_transfer",
            payload={
                "amount_cents": amount_cents,
                "destination": destination_account,
                # LLM-constructed payloads naturally include these descriptors:
                "transfer_type": "wire_transfer",   # matches "transfer", "wire"
                "swift": swift_code,                # matches "swift"
                "bulk": amount_cents > 1_000_000,   # matches "bulk"
                "memo": memo,
            },
        )

        if not gate_result.passed:
            logger.warning(
                "[gate] high_value_wire BLOCKED agent=%s amount=%d risk=%.3f",
                self._agent_id, amount_cents, gate_result.risk_score or 0,
            )
            return {
                "gated": True,
                "gate_reason": gate_result.reason,
                "risk_score": gate_result.risk_score,
                "threshold": gate_result.threshold,
                "action_required": "human_approval",
                "amount_cents": amount_cents,
            }

        # In production: enqueue to wire-transfer service with 4-eyes approval
        logger.info("[wire] would enqueue wire %d cents → %s", amount_cents, destination_account)
        return {
            "queued": True,
            "transfer_id": f"wire_{uuid.uuid4().hex[:12]}",
            "amount_cents": amount_cents,
            "destination": destination_account,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Agent — orchestrates tools to fulfill a payment workflow
# ─────────────────────────────────────────────────────────────────────────────

class PaymentAgent:
    """Simulates an LLM-driven payment agent orchestrating Stripe tools.

    In production this class would be driven by an LLM loop
    (LangChain, LangGraph, CrewAI, OpenAI Agents SDK) with tool calling.
    Here we hardcode scenarios to show the gate in action.
    """

    def __init__(self, agent_id: str) -> None:
        self._agent_id = agent_id
        self._tools = PaymentTools(agent_id=agent_id)

    def process_subscription_renewal(
        self,
        customer_id: str,
        plan_amount_cents: int,
    ) -> None:
        """Happy path: routine subscription charge."""
        print(f"\n[scenario] Subscription renewal: {customer_id} × ${plan_amount_cents/100:.2f}")
        record = self._tools.charge_customer(
            customer_id=customer_id,
            amount_cents=plan_amount_cents,
            description=f"Monthly subscription renewal — {customer_id}",
        )
        rs = f"{record.gate_result.risk_score:.3f}" if record.gate_result else "?"
        print(f"  status={record.status.value}  stripe_id={record.stripe_id}  "
              f"gate_passed={record.gate_result.passed if record.gate_result else '?'}  "
              f"risk_score={rs}")

    def process_refund_request(self, charge_id: str, amount_cents: int) -> None:
        """Customer requests a refund on a previous charge."""
        print(f"\n[scenario] Refund request: charge={charge_id} amount=${amount_cents/100:.2f}")
        result = self._tools.refund_payment(charge_id=charge_id, amount_cents=amount_cents)
        print(f"  result={result}")

    def attempt_bulk_payout(self, amount_cents: int, bank_account: str) -> None:
        """End-of-week bulk payout — will trigger gate due to payout risk category."""
        print(f"\n[scenario] Payout: ${amount_cents/100:.2f} → {bank_account}")
        result = self._tools.payout_to_bank(
            amount_cents=amount_cents,
            destination_bank_account=bank_account,
        )
        print(f"  result={result}")

    def attempt_wire_transfer(
        self,
        amount_cents: int,
        destination: str,
        swift: str,
    ) -> None:
        """High-value SWIFT wire — likely gated due to high_value_transfer risk category."""
        print(f"\n[scenario] Wire transfer: ${amount_cents/100:,.2f} → {destination} ({swift})")
        result = self._tools.high_value_wire(
            amount_cents=amount_cents,
            destination_account=destination,
            swift_code=swift,
            memo="Q2 vendor settlement",
        )
        if result.get("gated"):
            print(f"  GATED — action_required={result.get('action_required', 'review')}")
            print(f"  risk_score={result.get('risk_score'):.3f}  threshold={result.get('threshold'):.3f}")
        else:
            print(f"  result={result}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=== CapFence Fintech Payment Agent Demo ===")
    print(f"Audit log: {AUDIT_DB}")
    print()

    agent = PaymentAgent(agent_id="payment-agent-prod-1")

    # Scenario 1: routine low-risk charge → should PASS
    agent.process_subscription_renewal(
        customer_id="cus_abc123",
        plan_amount_cents=4900,  # $49.00
    )

    # Scenario 2: refund → should PASS (delta=0.4, generous threshold)
    agent.process_refund_request(
        charge_id="ch_demo_001",
        amount_cents=4900,
    )

    # Scenario 3: payout with explicit "payout" keyword → may trigger gate
    agent.attempt_bulk_payout(
        amount_cents=250000,  # $2,500.00 — weekly settlement
        bank_account="ba_demo_merchant_001",
    )

    # Scenario 4: high-value SWIFT wire → "wire", "transfer", "swift", "high_value" keywords hit
    agent.attempt_wire_transfer(
        amount_cents=4_800_000,  # $48,000
        destination="ACME Corp EU GmbH",
        swift="DEUTDEDBXXX",
    )

    # Scenario 5: another routine charge after decisions — gate tracks K/V drift
    agent.process_subscription_renewal(
        customer_id="cus_xyz789",
        plan_amount_cents=9900,  # $99.00
    )

    print()
    print("─" * 60)
    print("Audit log written. To verify chain integrity:")
    print(f"  capfence verify --audit-log {AUDIT_DB}")
    print()
    print("To replay this trace through the gate:")
    print("  capfence replay <trace.json> --policy <policy.yaml>")
    print()

    # Show final audit log summary
    from capfence.core.audit import AuditLogger
    audit = AuditLogger(db_path=AUDIT_DB)
    events = audit.get_events(limit=100)
    valid, errors = audit.verify()
    print(f"Audit log: {len(events)} entries, chain {'VALID' if valid else 'INVALID'}")
    print()
    blocked = [e for e in events if e["decision"] == "fail"]
    passed = [e for e in events if e["decision"] == "pass"]
    print(f"  Passed: {len(passed)}  Blocked: {len(blocked)}")
    for b in blocked:
        print(f"    blocked → {b['task_context']} (risk={b['risk_score']:.3f} > threshold={b['threshold']:.3f})")


if __name__ == "__main__":
    main()
