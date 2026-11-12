from __future__ import annotations

import dataclasses
import datetime as dt
import enum


class IntentKind(enum.StrEnum):
    SEND = "send"
    ARCHIVE = "archive"
    MOVE = "move"
    MARK = "mark"
    TRASH = "trash"


class ExecutionState(enum.StrEnum):
    ATTEMPTING = "ATTEMPTING"
    RETRYABLE = "RETRYABLE"
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"
    FAILED = "FAILED"


class ApprovalSource(enum.StrEnum):
    HUMAN = "human"
    POLICY = "policy"


@dataclasses.dataclass(frozen=True)
class Actor:
    subject: str
    client_id: str
    surface: str
    human_verified: bool


@dataclasses.dataclass(frozen=True)
class Draft:
    draft_id: str
    kind: IntentKind
    payload: dict
    payload_hash: str
    created_by: str
    created_client: str
    created_at: dt.datetime
    expires_at: dt.datetime


@dataclasses.dataclass(frozen=True)
class Approval:
    approval_id: str
    draft_id: str
    payload_hash: str
    approved_by: str
    approved_client: str
    approved_at: dt.datetime
    # A human approval is a durable work order and never expires (None); it can
    # only be executed or revoked. A policy approval expires with its draft.
    expires_at: dt.datetime | None
    approval_source: ApprovalSource
    consumed_at: dt.datetime | None = None
    revoked_at: dt.datetime | None = None

    def expired(self, now: dt.datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now


@dataclasses.dataclass(frozen=True)
class ApprovalRow:
    """One UI-visible pipeline entry: an approval with its draft and ledger
    fields, or a not-yet-approved, unexpired draft (``approval is None``).

    Both repositories return these raw rows from ``approval_rows``; every
    derived view (status, phase, counts, pages, queue position, activity)
    is computed once in ``ApprovalService`` from ``_approval_status`` and
    ``EXECUTION_PHASES`` — repositories never compute phases.
    """

    draft: Draft
    approval: Approval | None
    state: ExecutionState | None
    error_class: str | None
    attempt: int | None
    execution_updated_at: dt.datetime | None


@dataclasses.dataclass(frozen=True)
class ActionExecution:
    action_id: str
    approval_id: str
    draft_id: str
    kind: IntentKind
    payload_hash: str
    idempotency_key: str
    state: ExecutionState
    attempt: int
    created_at: dt.datetime
    updated_at: dt.datetime
    provider_object_id: str | None = None
    provider_result: dict | None = None
    error_class: str | None = None
    # Start of the current provider attempt; a retry or renewal moves it.
    attempted_at: dt.datetime | None = None

    @property
    def last_attempt_at(self) -> dt.datetime:
        return self.attempted_at or self.created_at
