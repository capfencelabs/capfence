"""Concurrency smoke tests for Gate.bypass."""
import threading

from capfence.core.gate import Gate


RISKY_PAYLOAD = {
    "action": "create_payout",
    "disburse": True,
    "amount": 95000,
    "payout": True,
    "transfer_to_bank": True,
}


def test_bypass_stack_concurrent_agents():
    """Two threads bypassing different agents should not corrupt each other's stack."""
    gate = Gate(taxonomy_path="financial")
    errors: list[str] = []

    def run_agent(agent_id: str, reason: str) -> None:
        try:
            for _ in range(50):
                with gate.bypass(agent_id, reason=reason):
                    r = gate.evaluate(agent_id, "payout", "stripe_payout", RISKY_PAYLOAD)
                    if not r.passed:
                        errors.append(f"{agent_id}: bypass failed to override")
        except Exception as e:
            errors.append(f"{agent_id}: {type(e).__name__}: {e}")

    threads = [
        threading.Thread(target=run_agent, args=(f"agent-{i}", f"reason-{i}"))
        for i in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"bypass corruption under concurrency: {errors}"
    # After all threads exit, no bypasses should remain active
    assert gate._bypass_stack == {}
