# Payments Dangerous Patterns

CapFence policy packs are starter authorization policies for common agent side effects. They are not universal security policies. Treat them as explicit defaults to adapt, test, and review.

Review payment requests that include:

- Refunds above the automatic approval threshold.
- Unknown or unapproved merchants.
- Missing idempotency keys.
- Currency mismatches.
- Bulk payouts or repeated retries.
