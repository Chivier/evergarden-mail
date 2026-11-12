"""Approval pipeline exceptions, tuning constants and executor protocol.

Every provider attempt has exactly three outcomes:

- **Applied** — the executor returns a result (success is a value, not an
  exception).
- **NotApplied** — ``ProviderDefinitelyRejected`` and its refinements: the
  provider provably did not apply the effect.
- **Unknown** — ``ProviderOutcomeUnknown`` and its refinement: the effect may
  or may not have landed.

What happens next depends on whether the operation is replay-safe
(``ApprovalService._replay_safe``): a UID-targeted mark or native move is
simply re-issued until the outcome settles; SEND and the copy-first move
strategies are never replayed and resolve read-only or end as FAILED.
"""

from __future__ import annotations

import datetime as dt
from typing import Protocol


class ApprovalError(RuntimeError):
    pass


class ProviderDefinitelyRejected(RuntimeError):
    """NotApplied: the provider proved that it did not apply the effect."""


class ProviderOutcomeUnknown(RuntimeError):
    """Unknown: the provider may have applied the effect before the failure."""


class ProviderPartialOutcome(ProviderOutcomeUnknown):
    """Unknown: the provider accepted only part of an indivisible action.

    Never reconciled and never replayed; it ends as OutcomeUnverified.
    """


class ProviderNotAttempted(ProviderDefinitelyRejected):
    """NotApplied before any mutation command: the approval stays usable."""


class ProviderSourceGone(ProviderDefinitelyRejected):
    """NotApplied and never applicable: the source message is gone and the
    destination does not hold it. The action ends as FAILED for every kind."""


class ProviderProvedNotApplied(ProviderDefinitelyRejected):
    """NotApplied, proven by read-only reconciliation. A replay-safe
    operation is re-issued; SEND and copy-first strategies end as FAILED."""


HUMAN_APPROVAL_SURFACES = frozenset({"approval-ui", "admin-cli"})
RETRY_BACKOFF_STEP_SECONDS = 60
RETRY_BACKOFF_MAX_SECONDS = 300
UNKNOWN_RECONCILE_INTERVAL = dt.timedelta(minutes=10)
# An outcome that stays unprovable this long after the attempt ends as FAILED
# (OutcomeUnverified); it is never replayed and stops blocking its message.
UNKNOWN_GIVE_UP_AFTER = dt.timedelta(hours=24)
OUTCOME_UNVERIFIED = "OutcomeUnverified"
EXECUTION_PAGE_STATUSES = frozenset({"all", "pending", "running", "confirmed", "failed"})
# User-facing phase of every fine-grained approval status. A human approval is
# a durable work order: it never expires, so "approval_expired" survives only
# for rows issued before the durable model (migration 006 closed the open ones).
EXECUTION_PHASES = {
    "pending_approval": "pending",
    "approval_expired": "failed",
    "revoked": "failed",
    "approved": "running",
    "blocked": "running",
    "awaiting_client": "running",
    "retryable": "running",
    "attempting": "running",
    "unknown": "running",
    "confirmed": "confirmed",
    "failed": "failed",
    "client_expired": "failed",
    "consumed": "failed",
}
ACTIVITY_WINDOW = dt.timedelta(minutes=10)
_APPROVAL_COLUMNS = (
    "approval_id,draft_id,payload_hash,approved_by,approved_client,"
    "approved_at,expires_at,approval_source,consumed_at,revoked_at"
)


class ApprovedActionExecutor(Protocol):
    def execute(self, payload: dict, idempotency_key: str) -> dict: ...

    def reconcile(self, payload: dict, idempotency_key: str) -> dict | None: ...
