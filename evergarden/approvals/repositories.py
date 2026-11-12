"""Approval and execution storage: in-memory and Postgres repositories."""

from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import enum
import hashlib
import json
import os
import threading
import uuid

import psycopg
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg.rows import dict_row

from evergarden import database
from evergarden.approvals.errors import (
    _APPROVAL_COLUMNS,
    ACTIVITY_WINDOW,
    RETRY_BACKOFF_MAX_SECONDS,
    RETRY_BACKOFF_STEP_SECONDS,
    ApprovalError,
    ProviderPartialOutcome,
)
from evergarden.approvals.models import (
    ActionExecution,
    Approval,
    ApprovalRow,
    ApprovalSource,
    Draft,
    ExecutionState,
    IntentKind,
)


class ApprovalRepository:
    """Thread-safe reference repository with one-shot consumption."""

    def __init__(self):
        self.drafts: dict[str, Draft] = {}
        self.approvals: dict[str, Approval] = {}
        self.executions: dict[str, ActionExecution] = {}
        self.dispatcher_status_row: dict | None = None
        self._lock = threading.RLock()

    def add_draft(self, draft: Draft) -> None:
        with self._lock:
            self.drafts[draft.draft_id] = draft

    def approval_rows(
        self,
        now: dt.datetime,
        *,
        pending_only: bool = False,
        include_payloads: bool = False,
    ) -> list[ApprovalRow]:
        """Raw UI rows; every derived view is computed in ApprovalService.

        ``include_payloads=False`` leaves every ``draft.payload`` empty, like
        the Postgres repository, so callers must fetch displayed payloads via
        ``get_drafts_batch``. ``pending_only`` restricts the result to
        unapproved, unexpired drafts.
        """

        def light(draft: Draft) -> Draft:
            if include_payloads:
                return copy.deepcopy(draft)
            return dataclasses.replace(draft, payload={})

        with self._lock:
            rows: list[ApprovalRow] = []
            approved_draft_ids: set[str] = set()
            for approval in self.approvals.values():
                approved_draft_ids.add(approval.draft_id)
                if pending_only:
                    continue
                execution = self.executions.get(approval.approval_id)
                rows.append(
                    ApprovalRow(
                        draft=light(self.drafts[approval.draft_id]),
                        approval=copy.deepcopy(approval),
                        state=execution.state if execution else None,
                        error_class=execution.error_class if execution else None,
                        attempt=execution.attempt if execution else None,
                        execution_updated_at=execution.updated_at if execution else None,
                    )
                )
            for draft in self.drafts.values():
                if draft.draft_id not in approved_draft_ids and draft.expires_at > now:
                    rows.append(
                        ApprovalRow(
                            draft=light(draft),
                            approval=None,
                            state=None,
                            error_class=None,
                            attempt=None,
                            execution_updated_at=None,
                        )
                    )
            return rows

    def add_approval(self, approval: Approval) -> None:
        with self._lock:
            if any(item.draft_id == approval.draft_id for item in self.approvals.values()):
                raise ApprovalError("draft already has an approval")
            self.approvals[approval.approval_id] = approval

    def _waiting(self, approval: Approval) -> bool:
        """Approved, never executed or provider-not-reached, and not revoked."""
        if approval.revoked_at is not None:
            return False
        execution = self.executions.get(approval.approval_id)
        if execution is None:
            return approval.consumed_at is None
        return execution.state is ExecutionState.RETRYABLE

    @staticmethod
    def _retry_due(execution: ActionExecution, now: dt.datetime) -> bool:
        delay = min(RETRY_BACKOFF_STEP_SECONDS * execution.attempt, RETRY_BACKOFF_MAX_SECONDS)
        return execution.updated_at <= now - dt.timedelta(seconds=delay)

    def ready_human_approvals(
        self,
        now: dt.datetime,
        *,
        kinds: frozenset[IntentKind],
        limit: int,
        offset: int = 0,
    ) -> list[tuple[str, str]]:
        with self._lock:
            ready = []
            for approval in sorted(
                self.approvals.values(), key=lambda a: (a.approved_at, a.approval_id)
            ):
                if (
                    approval.approval_source is not ApprovalSource.HUMAN
                    or approval.expired(now)
                    or self.drafts[approval.draft_id].kind not in kinds
                    or not self._waiting(approval)
                ):
                    continue
                execution = self.executions.get(approval.approval_id)
                if execution is None or self._retry_due(execution, now):
                    ready.append((approval.approval_id, approval.draft_id))
            return ready[offset : offset + limit]

    def ready_human_count(self, now: dt.datetime) -> int:
        with self._lock:
            return sum(
                1
                for approval in self.approvals.values()
                if approval.approval_source is ApprovalSource.HUMAN
                and not approval.expired(now)
                and self._waiting(approval)
            )

    def queue_position(self, approval_id: str, now: dt.datetime) -> int | None:
        """1-based place of a waiting human approval in the dispatcher's FIFO order."""
        with self._lock:
            approval = self.approvals.get(approval_id)
            if (
                approval is None
                or approval.approval_source is not ApprovalSource.HUMAN
                or approval.expired(now)
                or not self._waiting(approval)
            ):
                return None
            key = (approval.approved_at, approval.approval_id)
            return 1 + sum(
                1
                for other in self.approvals.values()
                if other.approval_source is ApprovalSource.HUMAN
                and not other.expired(now)
                and self._waiting(other)
                and (other.approved_at, other.approval_id) < key
            )

    def dispatch_activity(self, now: dt.datetime) -> dict:
        """The newest in-flight execution and human executions finished recently."""
        with self._lock:
            attempting = sorted(
                (e for e in self.executions.values() if e.state is ExecutionState.ATTEMPTING),
                key=lambda e: (e.updated_at, e.approval_id),
            )
            finished = sum(
                1
                for e in self.executions.values()
                if e.state in {ExecutionState.CONFIRMED, ExecutionState.FAILED}
                and e.updated_at > now - ACTIVITY_WINDOW
                and self.approvals[e.approval_id].approval_source is ApprovalSource.HUMAN
            )
            current = attempting[-1] if attempting else None
            return {
                "current": copy.deepcopy(self.drafts[current.draft_id]) if current else None,
                "started_at": current.updated_at if current else None,
                "finished_recent": finished,
            }

    def reconcilable_executions(
        self,
        now: dt.datetime,
        *,
        kinds: frozenset[IntentKind],
        attempting_before: dt.datetime,
        unknown_before: dt.datetime,
        give_up_before: dt.datetime,
        limit: int,
    ) -> list[tuple[str, str]]:
        with self._lock:
            rows = sorted(
                (
                    execution
                    for execution in self.executions.values()
                    if execution.kind in kinds
                    and (
                        (
                            execution.state is ExecutionState.ATTEMPTING
                            and execution.updated_at <= attempting_before
                        )
                        or (
                            execution.state is ExecutionState.UNKNOWN
                            and execution.updated_at <= unknown_before
                            and (
                                execution.error_class != ProviderPartialOutcome.__name__
                                or execution.last_attempt_at <= give_up_before
                            )
                        )
                    )
                ),
                key=lambda execution: (execution.updated_at, execution.approval_id),
            )
            return [(execution.approval_id, execution.draft_id) for execution in rows[:limit]]

    def expire_drafts(self, draft_ids: list[str], *, now: dt.datetime) -> list[str]:
        """End the review window of unapproved drafts that can no longer apply."""
        with self._lock:
            expired = []
            approved = {a.draft_id for a in self.approvals.values()}
            for draft_id in draft_ids:
                draft = self.drafts.get(draft_id)
                if draft is None or draft_id in approved or draft.expires_at <= now:
                    continue
                self.drafts[draft_id] = dataclasses.replace(draft, expires_at=now)
                expired.append(draft_id)
            return expired

    def unresolved_message_ids(self) -> set[str]:
        with self._lock:
            return {
                str(self.drafts[e.draft_id].payload["stable_message_id"])
                for e in self.executions.values()
                if e.state in {ExecutionState.UNKNOWN, ExecutionState.ATTEMPTING}
                and self.drafts[e.draft_id].payload.get("stable_message_id")
            }

    def revoke_approvals(self, items: list[tuple[str, str]], *, now: dt.datetime) -> list[dict]:
        """Revoke waiting human approvals; a claimed execution can no longer be revoked."""
        with self._lock:
            revoked = []
            for draft_id, payload_hash in items:
                approval = next(
                    (a for a in self.approvals.values() if a.draft_id == draft_id), None
                )
                if (
                    approval is None
                    or approval.payload_hash != payload_hash
                    or approval.approval_source is not ApprovalSource.HUMAN
                    # Mirror the Postgres repository: a legacy pre-006 expired
                    # approval is already dead and is not revoked again.
                    or (approval.expires_at is not None and approval.expires_at <= now)
                    or not self._waiting(approval)
                ):
                    continue
                execution = self.executions.get(approval.approval_id)
                self.approvals[approval.approval_id] = dataclasses.replace(approval, revoked_at=now)
                revoked.append(
                    {
                        "approval_id": approval.approval_id,
                        "draft_id": approval.draft_id,
                        "previous_state": execution.state.value if execution else None,
                    }
                )
            return revoked

    def record_dispatcher_status(
        self,
        *,
        host: str,
        kinds: list[str],
        last_scan_at: dt.datetime,
        last_error_class: str | None,
        last_item_error_class: str | None,
        last_result: dict,
    ) -> None:
        with self._lock:
            self.dispatcher_status_row = {
                "host": host,
                "kinds": list(kinds),
                "last_scan_at": last_scan_at,
                "last_error_class": last_error_class,
                "last_item_error_class": last_item_error_class,
                "last_result": copy.deepcopy(last_result),
                "updated_at": last_scan_at,
            }

    def dispatcher_status(self) -> dict | None:
        with self._lock:
            return copy.deepcopy(self.dispatcher_status_row)

    def get_draft(self, draft_id: str) -> Draft:
        with self._lock:
            try:
                return copy.deepcopy(self.drafts[draft_id])
            except KeyError as exc:
                raise ApprovalError("draft not found") from exc

    def get_drafts_batch(self, draft_ids: list[str]) -> dict[str, Draft]:
        with self._lock:
            return {
                draft_id: copy.deepcopy(self.drafts[draft_id])
                for draft_id in draft_ids
                if draft_id in self.drafts
            }

    def add_approvals_batch(self, approvals: list[Approval]) -> set[str]:
        with self._lock:
            inserted: set[str] = set()
            approved = {item.draft_id for item in self.approvals.values()}
            for approval in approvals:
                if approval.draft_id in approved:
                    continue
                self.approvals[approval.approval_id] = approval
                approved.add(approval.draft_id)
                inserted.add(approval.draft_id)
            return inserted

    def get_approval_for_draft(self, draft_id: str) -> Approval | None:
        with self._lock:
            match = next(
                (item for item in self.approvals.values() if item.draft_id == draft_id), None
            )
            return copy.deepcopy(match)

    def get_execution_for_approval(self, approval_id: str) -> ActionExecution | None:
        with self._lock:
            execution = self.executions.get(approval_id)
            return copy.deepcopy(execution)

    def location_execution_summaries(self) -> dict[str, list[dict]]:
        with self._lock:
            result: dict[str, list[dict]] = {}
            for execution in self.executions.values():
                draft = self.drafts[execution.draft_id]
                mid = draft.payload.get("stable_message_id")
                if mid:
                    result.setdefault(mid, []).append(
                        {
                            "action_id": execution.action_id,
                            "draft_id": execution.draft_id,
                            "kind": execution.kind.value,
                            "state": execution.state.value,
                            "updated_at": execution.updated_at.isoformat(),
                            "source_folder": draft.payload.get("source_folder"),
                            "destination": draft.payload.get("destination"),
                        }
                    )
            return result

    def consume(
        self, approval_id: str, draft_id: str, payload_hash: str, now: dt.datetime
    ) -> Approval:
        with self._lock:
            try:
                approval = self.approvals[approval_id]
            except KeyError as exc:
                raise ApprovalError("approval not found") from exc
            if approval.consumed_at:
                raise ApprovalError("approval is already consumed")
            if approval.draft_id != draft_id:
                raise ApprovalError("approval belongs to a different draft")
            if approval.revoked_at is not None:
                raise ApprovalError("approval is revoked")
            if approval.expired(now):
                raise ApprovalError("approval is expired")
            if approval.payload_hash != payload_hash:
                raise ApprovalError("approval payload hash does not match")
            consumed = dataclasses.replace(approval, consumed_at=now)
            self.approvals[approval_id] = consumed
            return consumed

    def claim_execution(
        self,
        *,
        approval_id: str,
        draft_id: str,
        kind: IntentKind,
        payload_hash: str,
        now: dt.datetime,
    ) -> tuple[ActionExecution, bool]:
        with self._lock:
            existing = self.executions.get(approval_id)
            if existing:
                self._validate_execution_identity(existing, draft_id, kind, payload_hash)
                approval = self.approvals[approval_id]
                if (
                    existing.state is ExecutionState.RETRYABLE
                    and approval.revoked_at is None
                    and not approval.expired(now)
                ):
                    retried = dataclasses.replace(
                        existing,
                        state=ExecutionState.ATTEMPTING,
                        attempt=existing.attempt + 1,
                        error_class=None,
                        updated_at=now,
                        attempted_at=now,
                    )
                    self.executions[approval_id] = retried
                    return copy.deepcopy(retried), True
                return copy.deepcopy(existing), False
            self.consume(approval_id, draft_id, payload_hash, now)
            idempotency_key = hashlib.sha256(f"{approval_id}\0{payload_hash}".encode()).hexdigest()
            execution = ActionExecution(
                action_id=str(uuid.uuid4()),
                approval_id=approval_id,
                draft_id=draft_id,
                kind=kind,
                payload_hash=payload_hash,
                idempotency_key=idempotency_key,
                state=ExecutionState.ATTEMPTING,
                attempt=1,
                created_at=now,
                updated_at=now,
                attempted_at=now,
            )
            self.executions[approval_id] = execution
            return copy.deepcopy(execution), True

    def transition_execution(
        self,
        approval_id: str,
        *,
        expected: frozenset[ExecutionState],
        state: ExecutionState,
        now: dt.datetime,
        provider_object_id: str | None = None,
        provider_result: dict | None = None,
        error_class: str | None = None,
    ) -> ActionExecution:
        with self._lock:
            try:
                execution = self.executions[approval_id]
            except KeyError as exc:
                raise ApprovalError("action execution not found") from exc
            if execution.state not in expected:
                raise ApprovalError("action execution state changed concurrently")
            updated = dataclasses.replace(
                execution,
                state=state,
                provider_object_id=provider_object_id,
                provider_result=copy.deepcopy(provider_result),
                error_class=error_class,
                updated_at=now,
            )
            self.executions[approval_id] = updated
            return copy.deepcopy(updated)

    @staticmethod
    def _validate_execution_identity(
        execution: ActionExecution,
        draft_id: str,
        kind: IntentKind,
        payload_hash: str,
    ) -> None:
        if (
            execution.draft_id != draft_id
            or execution.kind is not kind
            or execution.payload_hash != payload_hash
        ):
            raise ApprovalError("action execution identity does not match the approved draft")


class PostgresApprovalRepository:
    """Cross-process repository with host-bound encrypted draft payloads."""

    def __init__(self, database_url: str, *, key: bytes, host_id: str):
        if len(key) != 32:
            raise ApprovalError("approval encryption requires a 32-byte key")
        self.database_url = database_url
        self.host_id = host_id
        self._aes = AESGCM(key)

    def _aad(self, draft_id: str, payload_hash: str) -> bytes:
        return f"evergarden:approval:v1:{self.host_id}:{draft_id}:{payload_hash}".encode()

    def _batch_connection(self):
        # Bound connection, query and lock waits so an unavailable database
        # cannot indefinitely occupy a review request or worker thread.
        return database.connect(self.database_url, row_factory=dict_row)

    @staticmethod
    def _approval_from_row(row: dict, *, expires_key: str = "expires_at") -> Approval:
        return Approval(
            approval_id=str(row["approval_id"]),
            draft_id=str(row["draft_id"]),
            payload_hash=str(row["payload_hash"]),
            approved_by=str(row["approved_by"]),
            approved_client=str(row["approved_client"]),
            approved_at=row["approved_at"],
            expires_at=row[expires_key],
            approval_source=ApprovalSource(str(row["approval_source"])),
            consumed_at=row["consumed_at"],
            revoked_at=row["revoked_at"],
        )

    def ready_human_approvals(
        self,
        now: dt.datetime,
        *,
        kinds: frozenset[IntentKind],
        limit: int,
        offset: int = 0,
    ) -> list[tuple[str, str]]:
        with self._batch_connection() as conn:
            rows = conn.execute(
                """
                SELECT a.approval_id,a.draft_id FROM approvals a
                JOIN approval_drafts d USING(draft_id)
                LEFT JOIN mail_action_ledger l USING(approval_id)
                WHERE a.approval_source='human' AND d.kind = ANY(%s)
                  AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at>%s)
                  AND ((l.approval_id IS NULL AND a.consumed_at IS NULL)
                    OR (l.state='RETRYABLE'
                        AND l.updated_at <= %s - make_interval(
                              secs => LEAST(%s * l.attempt, %s))))
                ORDER BY a.approved_at,a.approval_id LIMIT %s OFFSET %s
                """,
                (
                    [kind.value for kind in kinds],
                    now,
                    now,
                    RETRY_BACKOFF_STEP_SECONDS,
                    RETRY_BACKOFF_MAX_SECONDS,
                    limit,
                    offset,
                ),
            ).fetchall()
        return [(str(row["approval_id"]), str(row["draft_id"])) for row in rows]

    def ready_human_count(self, now: dt.datetime) -> int:
        with self._batch_connection() as conn:
            row = conn.execute(
                """
                SELECT count(*) AS ready FROM approvals a
                LEFT JOIN mail_action_ledger l USING(approval_id)
                WHERE a.approval_source='human'
                  AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at>%s)
                  AND ((l.approval_id IS NULL AND a.consumed_at IS NULL) OR l.state='RETRYABLE')
                """,
                (now,),
            ).fetchone()
        return int(row["ready"])

    def queue_position(self, approval_id: str, now: dt.datetime) -> int | None:
        """1-based place of a waiting human approval in the dispatcher's FIFO order."""
        with self._batch_connection() as conn:
            row = conn.execute(
                f"""
                WITH waiting AS (
                  SELECT a.approval_id,a.approved_at FROM approvals a
                  LEFT JOIN mail_action_ledger l USING(approval_id)
                  WHERE a.approval_source='human' AND a.revoked_at IS NULL
                    AND (a.expires_at IS NULL OR a.expires_at>%(now)s) AND {self._OPEN_SQL})
                SELECT (SELECT count(*) FROM waiting w
                        WHERE (w.approved_at,w.approval_id) < (me.approved_at,me.approval_id)) + 1
                       AS position
                FROM waiting me WHERE me.approval_id=%(approval_id)s
                """,  # noqa: S608 - fixed SQL fragment
                {"now": now, "approval_id": approval_id},
            ).fetchone()
        return int(row["position"]) if row else None

    def dispatch_activity(self, now: dt.datetime) -> dict:
        """The newest in-flight execution and human executions finished recently."""
        with self._batch_connection() as conn:
            current = conn.execute(
                "SELECT draft_id,updated_at FROM mail_action_ledger WHERE state='ATTEMPTING' "
                "ORDER BY updated_at DESC,approval_id DESC LIMIT 1"
            ).fetchone()
            finished = conn.execute(
                """
                SELECT count(*) AS finished FROM mail_action_ledger l
                JOIN approvals a USING(approval_id)
                WHERE a.approval_source='human' AND l.state IN ('CONFIRMED','FAILED')
                  AND l.updated_at>%s
                """,
                (now - ACTIVITY_WINDOW,),
            ).fetchone()["finished"]
        return {
            "current": self.get_draft(str(current["draft_id"])) if current else None,
            "started_at": current["updated_at"] if current else None,
            "finished_recent": int(finished),
        }

    def reconcilable_executions(
        self,
        now: dt.datetime,
        *,
        kinds: frozenset[IntentKind],
        attempting_before: dt.datetime,
        unknown_before: dt.datetime,
        give_up_before: dt.datetime,
        limit: int,
    ) -> list[tuple[str, str]]:
        with self._batch_connection() as conn:
            rows = conn.execute(
                """
                SELECT l.approval_id,l.draft_id FROM mail_action_ledger l
                WHERE l.kind = ANY(%s) AND ((l.state='ATTEMPTING' AND l.updated_at<=%s)
                  OR (l.state='UNKNOWN' AND l.updated_at<=%s
                      AND (l.error_class IS DISTINCT FROM 'ProviderPartialOutcome'
                           OR l.attempted_at<=%s)))
                ORDER BY l.updated_at,l.approval_id LIMIT %s
                """,
                (
                    [kind.value for kind in kinds],
                    attempting_before,
                    unknown_before,
                    give_up_before,
                    limit,
                ),
            ).fetchall()
        return [(str(row["approval_id"]), str(row["draft_id"])) for row in rows]

    def revoke_approvals(self, items: list[tuple[str, str]], *, now: dt.datetime) -> list[dict]:
        """Revoke waiting human approvals; a claimed execution can no longer be revoked."""
        if not items:
            return []
        with self._batch_connection() as conn:
            # Lock the approval rows first; the retry claim locks the same rows
            # before reopening a RETRYABLE ledger row, so the two serialize.
            locked = conn.execute(
                """
                SELECT a.approval_id FROM approvals a
                JOIN (SELECT * FROM unnest(%(draft_ids)s::uuid[],%(hashes)s::text[]))
                     AS r(draft_id,payload_hash)
                  ON r.draft_id=a.draft_id AND r.payload_hash=a.payload_hash
                WHERE a.approval_source='human' AND a.revoked_at IS NULL
                  AND (a.expires_at IS NULL OR a.expires_at>%(now)s)
                ORDER BY a.approval_id
                FOR UPDATE OF a
                """,
                {
                    "draft_ids": [draft_id for draft_id, _ in items],
                    "hashes": [payload_hash for _, payload_hash in items],
                    "now": now,
                },
            ).fetchall()
            if not locked:
                return []
            # With the locks held this statement reads the ledger under a fresh
            # snapshot: a retry claim either committed before (the row is
            # ATTEMPTING and stays untouched) or is waiting on these locks and
            # will then see revoked_at.
            rows = conn.execute(
                """
                UPDATE approvals a SET revoked_at=%(now)s
                FROM (SELECT w.approval_id,l.state AS previous_state
                      FROM approvals w LEFT JOIN mail_action_ledger l USING(approval_id)
                      WHERE w.approval_id=ANY(%(approval_ids)s::uuid[])
                        AND ((l.approval_id IS NULL AND w.consumed_at IS NULL)
                             OR l.state='RETRYABLE')) t
                WHERE a.approval_id=t.approval_id
                RETURNING a.approval_id,a.draft_id,t.previous_state
                """,
                {
                    "now": now,
                    "approval_ids": [row["approval_id"] for row in locked],
                },
            ).fetchall()
        return [
            {
                "approval_id": str(row["approval_id"]),
                "draft_id": str(row["draft_id"]),
                "previous_state": row["previous_state"],
            }
            for row in rows
        ]

    def record_dispatcher_status(
        self,
        *,
        host: str,
        kinds: list[str],
        last_scan_at: dt.datetime,
        last_error_class: str | None,
        last_item_error_class: str | None,
        last_result: dict,
    ) -> None:
        with self._batch_connection() as conn:
            conn.execute(
                """
                INSERT INTO approval_dispatcher_status(
                  singleton,host,kinds,last_scan_at,last_error_class,last_item_error_class,
                  last_result,updated_at
                ) VALUES (TRUE,%s,%s,%s,%s,%s,%s::jsonb,now())
                ON CONFLICT (singleton) DO UPDATE SET
                  host=EXCLUDED.host,kinds=EXCLUDED.kinds,last_scan_at=EXCLUDED.last_scan_at,
                  last_error_class=EXCLUDED.last_error_class,
                  last_item_error_class=EXCLUDED.last_item_error_class,
                  last_result=EXCLUDED.last_result,updated_at=now()
                """,
                (
                    host,
                    list(kinds),
                    last_scan_at,
                    last_error_class,
                    last_item_error_class,
                    json.dumps(last_result, sort_keys=True),
                ),
            )

    def dispatcher_status(self) -> dict | None:
        with self._batch_connection() as conn:
            row = conn.execute(
                "SELECT host,kinds,last_scan_at,last_error_class,last_item_error_class,"
                "last_result,updated_at FROM approval_dispatcher_status WHERE singleton"
            ).fetchone()
        return dict(row) if row else None

    def expire_drafts(self, draft_ids: list[str], *, now: dt.datetime) -> list[str]:
        """End the review window of unapproved drafts that can no longer apply.

        Only ``expires_at`` is shortened; payload and hash stay immutable, and a
        draft that already has an approval is never touched.
        """
        if not draft_ids:
            return []
        with self._batch_connection() as conn:
            rows = conn.execute(
                """
                UPDATE approval_drafts d SET expires_at=%(now)s
                WHERE d.draft_id=ANY(%(ids)s::uuid[]) AND d.expires_at>%(now)s
                  AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.draft_id=d.draft_id)
                RETURNING d.draft_id
                """,
                {"ids": draft_ids, "now": now},
            ).fetchall()
        return [str(row["draft_id"]) for row in rows]

    def unresolved_message_ids(self) -> set[str]:
        with self._batch_connection() as conn:
            rows = conn.execute(
                """
                SELECT d.draft_id,d.payload_hash,d.encrypted_payload
                FROM mail_action_ledger l JOIN approval_drafts d USING(draft_id)
                WHERE l.state IN ('UNKNOWN','ATTEMPTING')
                """
            ).fetchall()
        return {
            str(payload["stable_message_id"])
            for row in rows
            if (payload := self._decrypt(row)).get("stable_message_id")
        }

    def location_execution_summaries(self) -> dict[str, list[dict]]:
        """Decrypt identities internally; return only locator/action metadata."""
        with self._batch_connection() as conn:
            conn.execute("SET TRANSACTION READ ONLY")
            rows = conn.execute(
                "SELECT d.draft_id,d.payload_hash,d.encrypted_payload,"
                "l.action_id,l.kind,l.state,l.updated_at "
                "FROM mail_action_ledger l JOIN approval_drafts d USING(draft_id) "
                "WHERE l.kind IN ('archive','trash','move','mark')"
            ).fetchall()
        result: dict[str, list[dict]] = {}
        for row in rows:
            payload = self._decrypt(row)
            mid = payload.get("stable_message_id")
            if mid:
                result.setdefault(mid, []).append(
                    {
                        "action_id": str(row["action_id"]),
                        "draft_id": str(row["draft_id"]),
                        "kind": str(row["kind"]),
                        "state": str(row["state"]),
                        "updated_at": row["updated_at"].isoformat(),
                        "source_folder": payload.get("source_folder"),
                        "destination": payload.get("destination"),
                    }
                )
        return result

    # Approved and never executed, or stopped before the provider was reached.
    # Shared by ready_human_approvals/ready_human_count/queue_position and the
    # open-first ordering of approval_rows; this is dispatcher eligibility
    # logic, not a user-facing phase (phases are computed in ApprovalService).
    _OPEN_SQL = "((l.approval_id IS NULL AND a.consumed_at IS NULL) OR l.state='RETRYABLE')"

    # Bound for one UI snapshot: the service pages and counts over the newest
    # rows only. Open approvals and pending drafts sort first, so truncation
    # can only drop settled history (their counts undercount past the bound).
    UI_ROWS_BOUND = 5000

    def approval_rows(
        self,
        now: dt.datetime,
        *,
        pending_only: bool = False,
        include_payloads: bool = False,
    ) -> list[ApprovalRow]:
        """Raw UI rows; every derived view is computed in ApprovalService.

        ``include_payloads=False`` skips the per-row AES decryption and leaves
        every ``draft.payload`` empty — enough for phases, counts, ordering
        and identities; callers fetch the payloads of the rows they actually
        display through ``get_drafts_batch``. ``pending_only`` restricts the
        result to unapproved, unexpired drafts.
        """
        query = f"""
            SELECT * FROM (
              SELECT d.draft_id,d.kind,d.payload_hash,d.encrypted_payload,d.created_by,
                     d.client_id,d.expires_at,d.created_at,
                     a.approval_id,a.approved_by,a.approved_client,a.approved_at,
                     a.expires_at AS approval_expires_at,a.consumed_at,a.approval_source,
                     a.revoked_at,
                     l.state AS execution_state,l.error_class,l.attempt,
                     l.updated_at AS execution_updated_at,
                     a.approved_at AS sort_at,a.approval_id::text AS sort_key,
                     ({self._OPEN_SQL})::int AS open_row
              FROM approvals a JOIN approval_drafts d USING(draft_id)
              LEFT JOIN mail_action_ledger l USING(approval_id)
              WHERE NOT %(pending_only)s
              UNION ALL
              SELECT d.draft_id,d.kind,d.payload_hash,d.encrypted_payload,d.created_by,
                     d.client_id,d.expires_at,d.created_at,
                     NULL::uuid,NULL,NULL,NULL::timestamptz,NULL::timestamptz,
                     NULL::timestamptz,NULL,NULL::timestamptz,NULL,NULL,NULL::integer,
                     NULL::timestamptz,d.created_at,d.draft_id::text,1
              FROM approval_drafts d
              WHERE d.expires_at>%(now)s
                AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.draft_id=d.draft_id)
            ) x ORDER BY x.open_row DESC,x.sort_at DESC,x.sort_key DESC LIMIT %(bound)s
            """  # noqa: S608 - fixed SQL fragments; values are bound parameters
        with self._batch_connection() as conn:
            rows = conn.execute(
                query,
                {"now": now, "bound": self.UI_ROWS_BOUND, "pending_only": pending_only},
            ).fetchall()
        return [
            ApprovalRow(
                draft=self._draft_from_row(row)
                if include_payloads
                else self._draft_from_row_without_payload(row),
                approval=self._approval_from_row(row, expires_key="approval_expires_at")
                if row["approval_id"] is not None
                else None,
                state=ExecutionState(str(row["execution_state"]))
                if row["execution_state"]
                else None,
                error_class=row["error_class"],
                attempt=row["attempt"],
                execution_updated_at=row["execution_updated_at"],
            )
            for row in rows
        ]

    def _draft_from_row_without_payload(self, row: dict) -> Draft:
        return Draft(
            draft_id=str(row["draft_id"]),
            kind=IntentKind(str(row["kind"])),
            payload={},
            payload_hash=str(row["payload_hash"]),
            created_by=str(row["created_by"]),
            created_client=str(row["client_id"]),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def _draft_from_row(self, row: dict) -> Draft:
        return Draft(
            draft_id=str(row["draft_id"]),
            kind=IntentKind(str(row["kind"])),
            payload=self._decrypt(row),
            payload_hash=str(row["payload_hash"]),
            created_by=str(row["created_by"]),
            created_client=str(row["client_id"]),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def _encrypt(self, draft: Draft) -> bytes:
        nonce = os.urandom(12)
        payload = json.dumps(
            draft.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        return nonce + self._aes.encrypt(
            nonce, payload, self._aad(draft.draft_id, draft.payload_hash)
        )

    def _decrypt(self, row: dict) -> dict:
        blob = bytes(row["encrypted_payload"])
        if len(blob) < 29:
            raise ApprovalError("encrypted approval payload is malformed")
        try:
            plaintext = self._aes.decrypt(
                blob[:12],
                blob[12:],
                self._aad(str(row["draft_id"]), str(row["payload_hash"])),
            )
            value = json.loads(plaintext)
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApprovalError("approval payload authentication failed") from exc
        if not isinstance(value, dict):
            raise ApprovalError("approval payload must be an object")
        return value

    def add_draft(self, draft: Draft) -> None:
        with database.connect(self.database_url) as conn:
            conn.execute(
                """
                INSERT INTO approval_drafts(
                  draft_id,kind,payload_hash,encrypted_payload,created_by,client_id,
                  expires_at,created_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    draft.draft_id,
                    draft.kind.value,
                    draft.payload_hash,
                    self._encrypt(draft),
                    draft.created_by,
                    draft.created_client,
                    draft.expires_at,
                    draft.created_at,
                ),
            )

    def add_approval(self, approval: Approval) -> None:
        try:
            with database.connect(self.database_url) as conn:
                conn.execute(
                    """
                    INSERT INTO approvals(
                      approval_id,draft_id,payload_hash,approved_by,approved_client,
                      approved_at,expires_at,approval_source,consumed_at,revoked_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        approval.approval_id,
                        approval.draft_id,
                        approval.payload_hash,
                        approval.approved_by,
                        approval.approved_client,
                        approval.approved_at,
                        approval.expires_at,
                        approval.approval_source.value,
                        approval.consumed_at,
                        approval.revoked_at,
                    ),
                )
        except psycopg.errors.UniqueViolation as exc:
            raise ApprovalError("draft already has an approval") from exc

    def get_draft(self, draft_id: str) -> Draft:
        with database.connect(self.database_url, row_factory=dict_row) as conn:
            row = conn.execute(
                """
                SELECT draft_id,kind,payload_hash,encrypted_payload,created_by,client_id,
                       expires_at,created_at
                FROM approval_drafts WHERE draft_id=%s
                """,
                (draft_id,),
            ).fetchone()
        if not row:
            raise ApprovalError("draft not found")
        return self._draft_from_row(row)

    def get_drafts_batch(self, draft_ids: list[str]) -> dict[str, Draft | ApprovalError]:
        valid_ids = {}
        for draft_id in draft_ids:
            try:
                valid_ids[draft_id] = str(uuid.UUID(draft_id))
            except ValueError:
                continue
        if not valid_ids:
            return {}
        with self._batch_connection() as conn:
            rows = conn.execute(
                """
                SELECT draft_id,kind,payload_hash,encrypted_payload,created_by,client_id,
                       expires_at,created_at
                FROM approval_drafts WHERE draft_id=ANY(%s::uuid[])
                """,
                (list(valid_ids.values()),),
            ).fetchall()
        drafts: dict[str, Draft | ApprovalError] = {}
        for row in rows:
            try:
                drafts[str(row["draft_id"])] = self._draft_from_row(row)
            except ApprovalError as exc:
                # A damaged encrypted packet fails only its own approval.
                drafts[str(row["draft_id"])] = exc
        return {
            original: drafts[canonical]
            for original, canonical in valid_ids.items()
            if canonical in drafts
        }

    def add_approvals_batch(self, approvals: list[Approval]) -> set[str]:
        if not approvals:
            return set()
        # Acquire unique-key locks in the same order across overlapping batches.
        ordered = sorted(approvals, key=lambda approval: approval.draft_id)
        params = tuple(
            [
                value.value if isinstance(value := getattr(approval, field), enum.Enum) else value
                for approval in ordered
            ]
            for field in (
                "approval_id",
                "draft_id",
                "payload_hash",
                "approved_by",
                "approved_client",
                "approved_at",
                "expires_at",
                "approval_source",
                "consumed_at",
                "revoked_at",
            )
        )
        with self._batch_connection() as conn:
            rows = conn.execute(
                """
                INSERT INTO approvals(
                  approval_id,draft_id,payload_hash,approved_by,approved_client,
                  approved_at,expires_at,approval_source,consumed_at,revoked_at
                ) SELECT * FROM unnest(
                    %s::uuid[],%s::uuid[],%s::text[],%s::text[],%s::text[],
                    %s::timestamptz[],%s::timestamptz[],%s::text[],%s::timestamptz[],
                    %s::timestamptz[]
                )
                ON CONFLICT (draft_id) DO NOTHING
                RETURNING draft_id
                """,
                params,
            ).fetchall()
        return {str(row["draft_id"]) for row in rows}

    def get_approval_for_draft(self, draft_id: str) -> Approval | None:
        with database.connect(self.database_url, row_factory=dict_row) as conn:
            row = conn.execute(
                f"SELECT {_APPROVAL_COLUMNS} FROM approvals WHERE draft_id=%s",  # noqa: S608
                (draft_id,),
            ).fetchone()
        return self._approval_from_row(row) if row else None

    def get_execution_for_approval(self, approval_id: str) -> ActionExecution | None:
        columns = (
            "action_id,approval_id,draft_id,kind,payload_hash,idempotency_key,state,"
            "attempt,provider_object_id,provider_result,error_class,created_at,updated_at,attempted_at"
        )
        with database.connect(self.database_url, row_factory=dict_row) as conn:
            row = conn.execute(
                f"SELECT {columns} FROM mail_action_ledger WHERE approval_id=%s",  # noqa: S608
                (approval_id,),
            ).fetchone()
        return self._execution_from_row(row) if row else None

    def consume(
        self, approval_id: str, draft_id: str, payload_hash: str, now: dt.datetime
    ) -> Approval:
        with database.connect(self.database_url, row_factory=dict_row) as conn:
            row = conn.execute(
                f"""
                UPDATE approvals SET consumed_at=%s
                WHERE approval_id=%s AND draft_id=%s AND consumed_at IS NULL
                  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>%s)
                  AND payload_hash=%s
                RETURNING {_APPROVAL_COLUMNS}
                """,  # noqa: S608 - fixed RETURNING columns
                (now, approval_id, draft_id, now, payload_hash),
            ).fetchone()
        if not row:
            raise ApprovalError("approval is expired, changed, missing, or already consumed")
        return self._approval_from_row(row)

    @staticmethod
    def _execution_from_row(row: dict) -> ActionExecution:
        return ActionExecution(
            action_id=str(row["action_id"]),
            approval_id=str(row["approval_id"]),
            draft_id=str(row["draft_id"]),
            kind=IntentKind(str(row["kind"])),
            payload_hash=str(row["payload_hash"]),
            idempotency_key=str(row["idempotency_key"]),
            state=ExecutionState(str(row["state"])),
            attempt=int(row["attempt"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            provider_object_id=(
                str(row["provider_object_id"]) if row["provider_object_id"] is not None else None
            ),
            provider_result=copy.deepcopy(row["provider_result"]),
            error_class=str(row["error_class"]) if row["error_class"] else None,
            attempted_at=row.get("attempted_at"),
        )

    @staticmethod
    def _validate_execution_identity(
        execution: ActionExecution,
        draft_id: str,
        kind: IntentKind,
        payload_hash: str,
    ) -> None:
        ApprovalRepository._validate_execution_identity(execution, draft_id, kind, payload_hash)

    def claim_execution(
        self,
        *,
        approval_id: str,
        draft_id: str,
        kind: IntentKind,
        payload_hash: str,
        now: dt.datetime,
    ) -> tuple[ActionExecution, bool]:
        columns = (
            "action_id,approval_id,draft_id,kind,payload_hash,idempotency_key,state,"
            "attempt,provider_object_id,provider_result,error_class,created_at,updated_at,attempted_at"
        )
        with database.connect(self.database_url, row_factory=dict_row) as conn:
            existing = conn.execute(
                f"SELECT {columns} FROM mail_action_ledger "  # noqa: S608 - fixed columns
                "WHERE approval_id=%s FOR UPDATE",
                (approval_id,),
            ).fetchone()
            if existing:
                execution = self._execution_from_row(existing)
                self._validate_execution_identity(execution, draft_id, kind, payload_hash)
                if execution.state is ExecutionState.RETRYABLE:
                    # Lock the approval row before reopening the ledger row, so a
                    # concurrent revoke (which locks the same row first) either
                    # already committed — the fresh read below sees revoked_at —
                    # or waits and then finds this row ATTEMPTING.
                    conn.execute(
                        "SELECT approval_id FROM approvals WHERE approval_id=%s FOR UPDATE",
                        (approval_id,),
                    )
                    prefixed = ",".join(f"l.{column}" for column in columns.split(","))
                    retry_sql = f"""
                        UPDATE mail_action_ledger l
                        SET state='ATTEMPTING',attempt=l.attempt+1,error_class=NULL,updated_at=%s,
                            attempted_at=%s
                        FROM approvals a
                        WHERE l.approval_id=%s AND a.approval_id=l.approval_id
                          AND l.state='RETRYABLE' AND a.revoked_at IS NULL
                          AND (a.expires_at IS NULL OR a.expires_at>%s)
                        RETURNING {prefixed}
                        """  # noqa: S608 - fixed RETURNING columns
                    retried = conn.execute(retry_sql, (now, now, approval_id, now)).fetchone()
                    if retried:
                        execution = self._execution_from_row(retried)
                        self._validate_execution_identity(execution, draft_id, kind, payload_hash)
                        return execution, True
                return execution, False
            approval = conn.execute(
                """
                UPDATE approvals SET consumed_at=%s
                WHERE approval_id=%s AND draft_id=%s AND consumed_at IS NULL
                  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>%s)
                  AND payload_hash=%s
                RETURNING approval_id
                """,
                (now, approval_id, draft_id, now, payload_hash),
            ).fetchone()
            if not approval:
                # A concurrent claimant may have committed while this transaction
                # waited on the approval row. Re-read before reporting failure.
                existing = conn.execute(
                    f"SELECT {columns} FROM mail_action_ledger WHERE approval_id=%s",  # noqa: S608
                    (approval_id,),
                ).fetchone()
                if existing:
                    execution = self._execution_from_row(existing)
                    self._validate_execution_identity(execution, draft_id, kind, payload_hash)
                    return execution, False
                raise ApprovalError("approval is expired, changed, missing, or already consumed")
            action_id = uuid.uuid4()
            idempotency_key = hashlib.sha256(f"{approval_id}\0{payload_hash}".encode()).hexdigest()
            insert_sql = f"""
                INSERT INTO mail_action_ledger(
                  action_id,approval_id,draft_id,kind,payload_hash,idempotency_key,
                  state,attempt,created_at,updated_at,attempted_at
                ) VALUES (%s,%s,%s,%s,%s,%s,'ATTEMPTING',1,%s,%s,%s)
                RETURNING {columns}
                """  # noqa: S608 - fixed RETURNING columns
            row = conn.execute(
                insert_sql,
                (
                    action_id,
                    approval_id,
                    draft_id,
                    kind.value,
                    payload_hash,
                    idempotency_key,
                    now,
                    now,
                    now,
                ),
            ).fetchone()
        return self._execution_from_row(row), True

    def transition_execution(
        self,
        approval_id: str,
        *,
        expected: frozenset[ExecutionState],
        state: ExecutionState,
        now: dt.datetime,
        provider_object_id: str | None = None,
        provider_result: dict | None = None,
        error_class: str | None = None,
    ) -> ActionExecution:
        if not expected:
            raise ApprovalError("at least one expected execution state is required")
        expected_values = [item.value for item in expected]
        columns = (
            "action_id,approval_id,draft_id,kind,payload_hash,idempotency_key,state,"
            "attempt,provider_object_id,provider_result,error_class,created_at,updated_at,attempted_at"
        )
        with database.connect(self.database_url, row_factory=dict_row) as conn:
            update_sql = f"""
                UPDATE mail_action_ledger SET
                  state=%s,provider_object_id=%s,provider_result=%s::jsonb,
                  error_class=%s,updated_at=%s
                WHERE approval_id=%s AND state=ANY(%s)
                RETURNING {columns}
                """  # noqa: S608 - fixed RETURNING columns
            row = conn.execute(
                update_sql,
                (
                    state.value,
                    provider_object_id,
                    json.dumps(provider_result, ensure_ascii=False, sort_keys=True)
                    if provider_result is not None
                    else None,
                    error_class,
                    now,
                    approval_id,
                    expected_values,
                ),
            ).fetchone()
            if not row:
                raise ApprovalError("action execution state changed concurrently")
            if state is ExecutionState.CONFIRMED:
                conn.execute(
                    "UPDATE approvals SET provider_object_id=%s WHERE approval_id=%s",
                    (provider_object_id, approval_id),
                )
        return self._execution_from_row(row)
