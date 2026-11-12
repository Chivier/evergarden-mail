from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import logging
import re
import uuid
from collections.abc import Callable

from evergarden.approvals.errors import (  # noqa: F401
    _APPROVAL_COLUMNS,
    ACTIVITY_WINDOW,
    EXECUTION_PAGE_STATUSES,
    EXECUTION_PHASES,
    HUMAN_APPROVAL_SURFACES,
    OUTCOME_UNVERIFIED,
    RETRY_BACKOFF_MAX_SECONDS,
    RETRY_BACKOFF_STEP_SECONDS,
    UNKNOWN_GIVE_UP_AFTER,
    UNKNOWN_RECONCILE_INTERVAL,
    ApprovalError,
    ApprovedActionExecutor,
    ProviderDefinitelyRejected,
    ProviderNotAttempted,
    ProviderOutcomeUnknown,
    ProviderPartialOutcome,
    ProviderProvedNotApplied,
    ProviderSourceGone,
)
from evergarden.approvals.models import (
    ActionExecution,
    Actor,
    Approval,
    ApprovalRow,
    ApprovalSource,
    Draft,
    ExecutionState,
    IntentKind,
)
from evergarden.approvals.repositories import (
    ApprovalRepository,
    PostgresApprovalRepository,
)
from evergarden.automations.fence import FenceRejected, LeaseToken, SideEffect, SideEffectFence
from evergarden.mail.models import AccountConfig


def _canonical_hash(kind: IntentKind, payload: dict) -> str:
    canonical = json.dumps(
        {"kind": kind.value, "payload": payload},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# How long a draft waits for a human review (and bounds a policy approval).
DRAFT_LIFETIME = dt.timedelta(hours=6)
LOGGER = logging.getLogger(__name__)
# Drafts that act on one archived message; a confirmed location change
# (archive/move/trash) of that message makes every older pending one moot.
MESSAGE_KINDS = frozenset({IntentKind.ARCHIVE, IntentKind.MOVE, IntentKind.MARK, IntentKind.TRASH})
LOCATION_KINDS = frozenset({IntentKind.ARCHIVE, IntentKind.MOVE, IntentKind.TRASH})


class ApprovalService:
    def __init__(
        self,
        repository: ApprovalRepository | PostgresApprovalRepository,
        *,
        accounts: tuple[AccountConfig, ...] = (),
        now: Callable[[], dt.datetime] | None = None,
        stale_execution_after: dt.timedelta = dt.timedelta(minutes=5),
        auto_approve_kinds: frozenset[IntentKind] | frozenset[str] = frozenset(),
        uidplus_move_accounts: frozenset[str] = frozenset(),
        receive_only_accounts: frozenset[str] = frozenset(),
        draft_lifetime: dt.timedelta = DRAFT_LIFETIME,
    ):
        self.repository = repository
        self.draft_lifetime = draft_lifetime
        self.accounts = {account.alias: account for account in accounts}
        self.now = now or (lambda: dt.datetime.now(dt.UTC))
        self.stale_execution_after = stale_execution_after
        self.auto_approve_kinds = self._validate_auto_approve(auto_approve_kinds)
        self.uidplus_move_accounts = frozenset(uidplus_move_accounts)
        self.receive_only_accounts = frozenset(receive_only_accounts)

    @staticmethod
    def _validate_auto_approve(
        kinds: frozenset[IntentKind] | frozenset[str],
    ) -> frozenset[IntentKind]:
        resolved = frozenset(IntentKind(str(kind)) for kind in kinds)
        if IntentKind.TRASH in resolved:
            raise ApprovalError("trash can never be auto-approved; it requires a human approval")
        return resolved

    def prepare(
        self,
        *,
        kind: IntentKind,
        payload: dict,
        actor: Actor,
        lifetime: dt.timedelta | None = None,
        approval_lifetime: dt.timedelta | None = None,
    ) -> Draft:
        self._validate_payload(kind, payload)
        lifetime = self.draft_lifetime if lifetime is None else lifetime
        approval_lifetime = self.draft_lifetime if approval_lifetime is None else approval_lifetime
        now = self.now()
        mid = payload.get("stable_message_id")
        same: list[Draft] = []
        if kind in MESSAGE_KINDS and kind not in self.auto_approve_kinds and mid:
            # One pending review per message and kind: an identical request
            # returns the waiting draft, a changed one replaces it.
            same = [d for d in self._pending_for_message(str(mid)) if d.kind is kind]
            payload_hash = _canonical_hash(kind, payload)
            for existing in same:
                if existing.payload_hash == payload_hash:
                    return existing
        draft = Draft(
            draft_id=str(uuid.uuid4()),
            kind=kind,
            payload=copy.deepcopy(payload),
            payload_hash=_canonical_hash(kind, payload),
            created_by=actor.subject,
            created_client=actor.client_id,
            created_at=now,
            expires_at=now + lifetime,
        )
        self.repository.add_draft(draft)
        if same:
            self._expire_superseded([d.draft_id for d in same], reason="replaced")
        if kind in self.auto_approve_kinds:
            self._issue_approval(draft, actor, now=now, lifetime=approval_lifetime)
        return draft

    def _pending_for_message(self, stable_id: str) -> list[Draft]:
        """Unapproved, unexpired drafts (with payloads) acting on one message."""
        pending = [d for d in self._pending_drafts() if d.kind in MESSAGE_KINDS]
        return [
            d
            for d in self._with_payloads(pending)
            if str(d.payload.get("stable_message_id") or "") == stable_id
        ]

    def _expire_superseded(self, draft_ids: list[str], *, reason: str) -> list[str]:
        expired = self.repository.expire_drafts(draft_ids, now=self.now())
        if expired:
            LOGGER.info("approval_drafts_superseded reason=%s count=%d", reason, len(expired))
        return expired

    def supersede_after_effect(self, draft_id: str) -> list[str]:
        """After a confirmed archive/move/trash, retire the message's older pending drafts.

        Their source folder/UID no longer holds the message, so approving one
        could only fail (e.g. a Trash still waiting after an auto-archive).
        """
        draft = self.repository.get_draft(draft_id)
        mid = draft.payload.get("stable_message_id")
        if draft.kind not in LOCATION_KINDS or not mid:
            return []
        stale = [
            d.draft_id
            for d in self._pending_for_message(str(mid))
            if d.draft_id != draft_id and d.created_at <= self.now()
        ]
        return self._expire_superseded(stale, reason="message_moved") if stale else []

    def supersede_stale_drafts(self) -> list[str]:
        """One sweep over all pending drafts: retire those whose message moved since."""
        pending = [d for d in self._pending_drafts() if d.kind in MESSAGE_KINDS]
        if not pending:
            return []
        executions = self.repository.location_execution_summaries()
        stale: list[str] = []
        for draft in self._with_payloads(pending):
            mid = str(draft.payload.get("stable_message_id") or "")
            for item in executions.get(mid, []):
                if (
                    item["state"] == ExecutionState.CONFIRMED.value
                    and item["kind"] in {kind.value for kind in LOCATION_KINDS}
                    and item["draft_id"] != draft.draft_id
                    and dt.datetime.fromisoformat(item["updated_at"]) >= draft.created_at
                ):
                    stale.append(draft.draft_id)
                    break
        # Duplicates of one message and kind: keep the newest pending draft.
        newest: dict[tuple[str, IntentKind], Draft] = {}
        for draft in self._with_payloads(pending):
            mid = str(draft.payload.get("stable_message_id") or "")
            if not mid or draft.draft_id in stale:
                continue
            key = (mid, draft.kind)
            kept = newest.get(key)
            if kept is None:
                newest[key] = draft
            else:
                older = min(kept, draft, key=lambda d: (d.created_at, d.draft_id))
                newest[key] = kept if older is draft else draft
                stale.append(older.draft_id)
        return self._expire_superseded(stale, reason="sweep") if stale else []

    def _issue_approval(
        self,
        draft: Draft,
        actor: Actor,
        *,
        now: dt.datetime,
        # Bounds policy approvals only; a human approval never expires.
        lifetime: dt.timedelta = dt.timedelta(),
    ) -> Approval:
        source = (
            ApprovalSource.HUMAN
            if actor.human_verified and actor.surface in HUMAN_APPROVAL_SURFACES
            else ApprovalSource.POLICY
        )
        approval = Approval(
            approval_id=str(uuid.uuid4()),
            draft_id=draft.draft_id,
            payload_hash=draft.payload_hash,
            approved_by=actor.subject,
            approved_client=actor.client_id,
            approved_at=now,
            # Draft expiry bounds when a human may review it. A human approval
            # is a durable work order: it never expires and can only be
            # executed or revoked. A policy approval never outlives its draft.
            expires_at=None
            if source is ApprovalSource.HUMAN
            else min(draft.expires_at, now + lifetime),
            approval_source=source,
        )
        self.repository.add_approval(approval)
        return approval

    def approval_for(self, draft_id: str) -> Approval | None:
        """Return the approval already issued for a draft, if any."""
        return self.repository.get_approval_for_draft(draft_id)

    @staticmethod
    def _require_human(actor: Actor) -> None:
        if not actor.human_verified or actor.surface not in HUMAN_APPROVAL_SURFACES:
            raise ApprovalError("approval requires a human-verified approval surface")

    def approve(
        self,
        *,
        draft_id: str,
        payload_hash: str,
        actor: Actor,
    ) -> Approval:
        self._require_human(actor)
        draft = self.repository.get_draft(draft_id)
        now = self.now()
        if draft.expires_at <= now:
            raise ApprovalError("draft is expired")
        if payload_hash != draft.payload_hash:
            raise ApprovalError("draft payload changed before approval")
        return self._issue_approval(draft, actor, now=now)

    def approve_batch(
        self,
        *,
        items: list[tuple[str, str]],
        actor: Actor,
    ) -> list[dict]:
        self._require_human(actor)
        draft_map = self.repository.get_drafts_batch([draft_id for draft_id, _ in items])
        now = self.now()
        prepared: list[Approval] = []
        results: list[dict] = []
        positions: list[int] = []
        seen: set[str] = set()
        for draft_id, payload_hash in items:
            draft = draft_map.get(draft_id)
            result = {"draft_id": draft_id, "status": "failed"}
            results.append(result)
            try:
                if draft is None:
                    raise ApprovalError("draft not found")
                if isinstance(draft, ApprovalError):
                    raise draft
                if draft.draft_id in seen:
                    raise ApprovalError("duplicate draft IDs")
                seen.add(draft.draft_id)
                if draft.kind is not IntentKind.TRASH:
                    raise ApprovalError("batch approval only supports trash drafts")
                if draft.expires_at <= now:
                    raise ApprovalError("draft is expired")
                if payload_hash != draft.payload_hash:
                    raise ApprovalError("draft payload changed before approval")
            except ApprovalError as exc:
                result["detail"] = str(exc)
                continue
            positions.append(len(results) - 1)
            prepared.append(
                Approval(
                    approval_id=str(uuid.uuid4()),
                    draft_id=draft.draft_id,
                    payload_hash=draft.payload_hash,
                    approved_by=actor.subject,
                    approved_client=actor.client_id,
                    approved_at=now,
                    # A human approval is durable; it is executed or revoked.
                    expires_at=None,
                    approval_source=ApprovalSource.HUMAN,
                )
            )
        inserted = self.repository.add_approvals_batch(prepared)
        for position, approval in zip(positions, prepared, strict=True):
            result = results[position]
            if approval.draft_id in inserted:
                result.update(status="approved", approval=approval)
                continue
            existing = self.repository.get_approval_for_draft(approval.draft_id)
            if (
                existing is not None
                and existing.approval_source is ApprovalSource.HUMAN
                and existing.payload_hash == approval.payload_hash
            ):
                result.update(status="already_approved", approval=existing)
            else:
                result["detail"] = "draft already has an approval"
        return results

    def revoke(self, *, items: list[tuple[str, str]], actor: Actor) -> dict:
        """Revoke waiting human approvals so the dispatcher never claims them.

        Only an approval the executor has not claimed (never consumed, or
        stopped before the provider was reached) can be revoked. A claimed or
        finished execution is history and stays untouched.
        """
        self._require_human(actor)
        now = self.now()
        seen: set[str] = set()
        results: list[dict] = []
        canonical_ids: list[str] = []
        valid: list[tuple[str, str]] = []
        for draft_id, payload_hash in items:
            result: dict = {"draft_id": draft_id, "status": "failed"}
            results.append(result)
            try:
                # Canonicalise before binding to uuid[]: one malformed or
                # re-cased ID must fail only its own item, never the batch.
                canonical = str(uuid.UUID(draft_id))
            except ValueError:
                canonical_ids.append("")
                result["detail"] = "draft not found"
                continue
            canonical_ids.append(canonical)
            if canonical in seen:
                result["detail"] = "duplicate draft IDs"
                continue
            seen.add(canonical)
            valid.append((canonical, payload_hash))
        revoked = self.repository.revoke_approvals(valid, now=now)
        by_draft = {row["draft_id"]: row for row in revoked}
        for result, canonical in zip(results, canonical_ids, strict=True):
            if "detail" in result:
                continue
            row = by_draft.get(canonical)
            if row is None:
                result["detail"] = (
                    "NOT_REVOCABLE: not a revocable approval "
                    "(only approvals that have not started executing)"
                )
                continue
            result.update(status="revoked", approval_id=row["approval_id"])
        return {"results": results, "revoked": revoked}

    def _pending_drafts(self) -> list[Draft]:
        """Unapproved, unexpired drafts in FIFO order, without payloads."""
        rows = self.repository.approval_rows(self.now(), pending_only=True)
        return sorted(
            (row.draft for row in rows), key=lambda draft: (draft.created_at, draft.draft_id)
        )

    def _with_payloads(self, drafts: list[Draft]) -> list[Draft]:
        """Load the payloads of exactly the drafts a response will display."""
        loaded = self.repository.get_drafts_batch([draft.draft_id for draft in drafts])
        return [
            draft for item in drafts if isinstance(draft := loaded.get(item.draft_id, item), Draft)
        ]

    def pending_trash_page(self, *, limit: int, offset: int) -> dict:
        pending = self._pending_drafts()
        trash = [draft for draft in pending if draft.kind is IntentKind.TRASH]
        other = [draft for draft in pending if draft.kind is not IntentKind.TRASH]
        page = trash[offset : offset + limit + 1]
        return {
            "drafts": [
                self._review_packet(draft, status="pending_approval", include_packet=False)
                for draft in self._with_payloads(page[:limit])
            ],
            "has_more": len(page) > limit,
            "total": len(trash),
            "other_drafts": [
                self._review_packet(draft, status="pending_approval", include_packet=False)
                for draft in self._with_payloads(other[:200])
            ],
            "other_total": len(other),
        }

    def pending_trash_selection(self) -> list[dict[str, str]]:
        """Every pending Trash draft's identity, for the select-all approval."""
        return [
            {"draft_id": draft.draft_id, "payload_hash": draft.payload_hash}
            for draft in self._pending_drafts()
            if draft.kind is IntentKind.TRASH
        ]

    @staticmethod
    def _revocable(approval: Approval, status: str) -> bool:
        """A human may revoke a waiting approval the executor has not claimed."""
        return (
            approval.approval_source is ApprovalSource.HUMAN
            and approval.revoked_at is None
            and status in {"approved", "retryable", "blocked"}
        )

    @staticmethod
    def _approval_status(approval: Approval, state: ExecutionState | None, now: dt.datetime) -> str:
        human = approval.approval_source is ApprovalSource.HUMAN
        expired_label = "approval_expired" if human else "client_expired"
        if approval.revoked_at is not None and state in {None, ExecutionState.RETRYABLE}:
            return "revoked"
        if state is ExecutionState.RETRYABLE:
            return expired_label if approval.expired(now) else "retryable"
        if state is not None:
            return state.value.casefold()
        if approval.consumed_at is not None:
            return "consumed"
        if approval.expired(now):
            return expired_label
        return "approved" if human else "awaiting_client"

    def _row_status(self, row: ApprovalRow, now: dt.datetime) -> str:
        if row.approval is None:
            return "pending_approval"
        return self._approval_status(row.approval, row.state, now)

    def execution_page(self, *, limit: int, offset: int, status: str = "all") -> dict:
        if status not in EXECUTION_PAGE_STATUSES:
            raise ApprovalError("unknown execution status filter")
        now = self.now()
        rows = self.repository.approval_rows(now)
        counts = dict.fromkeys(EXECUTION_PAGE_STATUSES, 0)
        entries: list[tuple[dt.datetime, str, ApprovalRow, str, str]] = []
        for row in rows:
            item_status = self._row_status(row, now)
            phase = EXECUTION_PHASES[item_status]
            counts[phase] += 1
            sort_at = row.approval.approved_at if row.approval else row.draft.created_at
            sort_key = row.approval.approval_id if row.approval else row.draft.draft_id
            entries.append((sort_at, sort_key, row, item_status, phase))
        counts["all"] = sum(value for key, value in counts.items() if key != "all")
        entries.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
        selected = [entry for entry in entries if status in {"all", entry[4]}]
        page = selected[offset : offset + limit + 1]
        shown = page[:limit]
        # Rows arrive without payloads; load exactly the displayed drafts.
        loaded = self.repository.get_drafts_batch(
            [row.draft.draft_id for _at, _key, row, _status, _phase in shown]
        )
        unresolved = (
            self.repository.unresolved_message_ids()
            if any(item_status == "approved" for *_rest, item_status, _ in shown)
            else set()
        )
        items = []
        for _sort_at, _sort_key, row, item_status, _phase in shown:
            approval = row.approval
            draft = loaded.get(row.draft.draft_id)
            if not isinstance(draft, Draft):
                draft = row.draft
            item = self._review_packet(draft, status=item_status, include_packet=False)
            if item_status == "approved" and draft.payload.get("stable_message_id") in unresolved:
                item["status"] = "blocked"
                item["reason_code"] = "PROVIDER_OUTCOME_UNKNOWN"
            item["phase"] = EXECUTION_PHASES[item_status]
            item["approval"] = self.approval_summary(approval) if approval else None
            item["error_class"] = row.error_class
            item["attempt"] = row.attempt
            item["revocable"] = approval is not None and self._revocable(approval, item["status"])
            items.append(item)
        return {
            "drafts": items,
            "has_more": len(page) > limit,
            "counts": counts,
        }

    def ready_human_count(self) -> int:
        """Waiting human approvals the dispatcher will eventually claim."""
        return self.repository.ready_human_count(self.now())

    def dispatch_activity(self) -> dict:
        """What the server dispatcher is doing now, for reviewer feedback."""
        activity = self.repository.dispatch_activity(self.now())
        current = activity["current"]
        return {
            "current": {
                "draft_id": current.draft_id,
                "kind": current.kind.value,
                "subject": current.payload.get("subject"),
                "account": current.payload.get("account"),
                "started_at": activity["started_at"]
                .astimezone(dt.UTC)
                .isoformat(timespec="seconds"),
            }
            if current is not None
            else None,
            "finished_recent": activity["finished_recent"],
            "window_minutes": int(ACTIVITY_WINDOW.total_seconds() // 60),
        }

    def review(self, draft_id: str, *, include_packet: bool = True) -> dict:
        """Return the exact immutable packet and its approval/execution state."""
        draft = self.repository.get_draft(draft_id)
        approval = self.repository.get_approval_for_draft(draft_id)
        execution = (
            self.repository.get_execution_for_approval(approval.approval_id)
            if approval is not None
            else None
        )
        now = self.now()
        if approval is not None:
            status = self._approval_status(
                approval, execution.state if execution is not None else None, now
            )
        elif draft.expires_at <= now:
            status = "draft_expired"
        else:
            status = "pending_approval"
        if status == "approved" and draft.payload.get("stable_message_id") in (
            self.repository.unresolved_message_ids()
        ):
            status = "blocked"
        result = self._review_packet(draft, status=status, include_packet=include_packet)
        result["phase"] = EXECUTION_PHASES.get(status)
        result["queue_position"] = (
            self.repository.queue_position(approval.approval_id, now)
            if approval is not None and status == "approved"
            else None
        )
        if approval is not None:
            result["approval"] = self.approval_summary(approval)
            result["revocable"] = self._revocable(approval, status)
        result["error_class"] = execution.error_class if execution is not None else None
        result["attempt"] = execution.attempt if execution is not None else None
        if execution is not None:
            result["execution"] = self._execution_result(execution, replayed=True)
        return result

    @staticmethod
    def approval_summary(approval: Approval) -> dict:
        return {
            "approval_id": approval.approval_id,
            "approved_by": approval.approved_by,
            "approved_at": approval.approved_at.astimezone(dt.UTC).isoformat(timespec="seconds"),
            "expires_at": approval.expires_at.astimezone(dt.UTC).isoformat(timespec="seconds")
            if approval.expires_at is not None
            else None,
            "revoked_at": approval.revoked_at.astimezone(dt.UTC).isoformat(timespec="seconds")
            if approval.revoked_at is not None
            else None,
            "consumed": approval.consumed_at is not None,
            "source": approval.approval_source.value,
        }

    @staticmethod
    def _review_packet(draft: Draft, *, status: str, include_packet: bool) -> dict:
        result = {
            "draft_id": draft.draft_id,
            "kind": draft.kind.value,
            "payload_hash": draft.payload_hash,
            "review_packet": copy.deepcopy(draft.payload) if include_packet else None,
            "created_by": draft.created_by,
            "created_client": draft.created_client,
            "created_at": draft.created_at.astimezone(dt.UTC).isoformat(timespec="seconds"),
            "expires_at": draft.expires_at.astimezone(dt.UTC).isoformat(timespec="seconds"),
            "status": status,
            "approval": None,
            "execution": None,
        }
        if not include_packet:
            # Keep the list response small while retaining the fields needed
            # to identify a message before its full packet is requested.
            result["summary"] = {
                key: draft.payload[key]
                for key in (
                    "subject",
                    "sender",
                    "from",
                    "account",
                    "source_folder",
                    "source_uid",
                    "provider_message_id",
                    "stable_message_id",
                    "date_received",
                    "destination",
                    "recovery_of",
                    "recovery_error",
                )
                if key in draft.payload
            }
        return result

    def execute(self, **kwargs) -> dict:
        result = self._execute(**kwargs)
        if str(result.get("state")) == ExecutionState.CONFIRMED.value:
            try:
                self.supersede_after_effect(kwargs["draft_id"])
            except Exception as exc:  # housekeeping must never fail a confirmed action
                LOGGER.warning("approval_supersede_failed error_class=%s", type(exc).__name__)
        return result

    def _execute(
        self,
        *,
        approval_id: str,
        draft_id: str,
        current_payload: dict,
        fence: SideEffectFence,
        lease: LeaseToken | None,
        executor: ApprovedActionExecutor | Callable[[dict, str], dict],
        expected_kind: IntentKind | None = None,
        # Whether an unprovable replay-safe outcome may be re-issued here. A
        # reconcile sweep covers every kind read-only, but replaying is a
        # provider write and must honour the host's enabled-kind fence.
        replay_allowed: bool = True,
    ) -> dict:
        draft = self.repository.get_draft(draft_id)
        if expected_kind is not None and draft.kind is not expected_kind:
            raise ApprovalError("approved endpoint does not match the draft kind")
        current_hash = _canonical_hash(draft.kind, current_payload)
        if current_hash != draft.payload_hash:
            raise ApprovalError("payload changed after preparation")
        # An account can become receive-only after a durable approval was
        # issued (e.g. a Thunderbird bridge account gains native sync).
        # Reject before the claim so the approval is not consumed; removing
        # the alias from the bridge configuration makes it executable again.
        self._reject_receive_only(current_payload)
        effect = {
            IntentKind.SEND: SideEffect.SMTP_SEND,
            IntentKind.ARCHIVE: SideEffect.IMAP_MOVE,
            IntentKind.MOVE: SideEffect.IMAP_MOVE,
            IntentKind.MARK: SideEffect.IMAP_FLAG,
            IntentKind.TRASH: SideEffect.IMAP_TRASH_MOVE,
        }[draft.kind]
        # Fence before consuming so a fence rejection does not burn the
        # approval. Resuming an already-claimed execution is read-only unless
        # it replays, so the fence check happens at the replay site instead —
        # otherwise a fenced-off kind (e.g. trash toggled off) could never be
        # reconciled and its row would block the message forever.
        existing = self.repository.get_execution_for_approval(approval_id)
        resuming = existing is not None and existing.state is not ExecutionState.RETRYABLE
        if not resuming:
            fence.assert_allowed(effect, lease)
        now = self.now()
        execution, claimed = self.repository.claim_execution(
            approval_id=approval_id,
            draft_id=draft_id,
            kind=draft.kind,
            payload_hash=current_hash,
            now=now,
        )
        if not claimed:
            return self._resume_execution(
                execution,
                current_payload,
                executor,
                now,
                replay_allowed=replay_allowed,
                fence=fence,
                lease=lease,
                effect=effect,
            )
        try:
            result = self._execute_provider(executor, current_payload, execution.idempotency_key)
            safe_result = self._safe_provider_result(result)
        except ProviderNotAttempted:
            # No mailbox or SMTP command was issued; the approval stays usable.
            self.repository.transition_execution(
                approval_id,
                expected=frozenset({ExecutionState.ATTEMPTING}),
                state=ExecutionState.RETRYABLE,
                now=self.now(),
                error_class=ProviderNotAttempted.__name__,
            )
            raise
        except ProviderDefinitelyRejected as exc:
            self.repository.transition_execution(
                approval_id,
                expected=frozenset({ExecutionState.ATTEMPTING}),
                state=ExecutionState.FAILED,
                now=self.now(),
                error_class=type(exc).__name__,
            )
            raise
        except Exception as exc:
            self.repository.transition_execution(
                approval_id,
                expected=frozenset({ExecutionState.ATTEMPTING}),
                state=ExecutionState.UNKNOWN,
                now=self.now(),
                error_class=type(exc).__name__,
            )
            raise
        confirmed = self.repository.transition_execution(
            approval_id,
            expected=frozenset({ExecutionState.ATTEMPTING}),
            state=ExecutionState.CONFIRMED,
            now=self.now(),
            provider_object_id=self._provider_object_id(safe_result),
            provider_result=safe_result,
        )
        return self._execution_result(confirmed, replayed=False)

    def _record_inconclusive(
        self, execution: ActionExecution, error_class: str, *, give_up: bool = True
    ) -> None:
        """Mark a read-only reconciliation that could not prove the outcome.

        After ``UNKNOWN_GIVE_UP_AFTER`` the row ends as FAILED/OutcomeUnverified:
        it is never replayed or renewed, and it stops blocking its message. An
        unreachable provider (``give_up=False``) proves nothing and never ends it.
        """
        now = self.now()
        if give_up and execution.last_attempt_at <= now - UNKNOWN_GIVE_UP_AFTER:
            self.repository.transition_execution(
                execution.approval_id,
                expected=frozenset({execution.state}),
                state=ExecutionState.FAILED,
                now=now,
                provider_object_id=execution.provider_object_id,
                provider_result=execution.provider_result,
                error_class=OUTCOME_UNVERIFIED,
            )
        elif execution.state is ExecutionState.ATTEMPTING:
            self.repository.transition_execution(
                execution.approval_id,
                expected=frozenset({ExecutionState.ATTEMPTING}),
                state=ExecutionState.UNKNOWN,
                now=now,
                error_class=error_class,
            )
        elif execution.state is ExecutionState.UNKNOWN:
            # Keep the original cause; the newer timestamp backs off the sweep.
            self.repository.transition_execution(
                execution.approval_id,
                expected=frozenset({ExecutionState.UNKNOWN}),
                state=ExecutionState.UNKNOWN,
                now=now,
                provider_object_id=execution.provider_object_id,
                provider_result=execution.provider_result,
                error_class=execution.error_class,
            )

    @staticmethod
    def _replay_safe(kind: IntentKind, payload: dict) -> bool:
        """Whether re-issuing the approved operation is harmless.

        A UID-targeted flag change or native MOVE converges when repeated:
        the executor verifies source identity first and treats an
        already-moved message as applied. SEND duplicates mail, and both
        copy-first strategies (copy-preserve, UIDPLUS move) can duplicate the
        destination copy when the earlier COPY landed, so those keep the
        strict unknown-outcome handling and are never replayed.
        """
        if kind is IntentKind.MARK:
            return True
        if kind in {IntentKind.ARCHIVE, IntentKind.MOVE, IntentKind.TRASH}:
            return not payload.get("copy_preserve_source_fallback", False) and not payload.get(
                "uidplus_move_fallback", False
            )
        return False

    def _replay_execution(
        self,
        execution: ActionExecution,
        payload: dict,
        executor: ApprovedActionExecutor | Callable[[dict, str], dict],
    ) -> dict:
        """Re-issue an idempotent operation whose outcome stayed unprovable."""
        try:
            result = self._execute_provider(executor, payload, execution.idempotency_key)
            safe_result = self._safe_provider_result(result)
        except ProviderNotAttempted as exc:
            # The replay never reached the provider; the original outcome
            # stays unknown and proves nothing.
            self._record_inconclusive(execution, "ReconciliationUnavailable", give_up=False)
            raise ApprovalError(
                "provider outcome remains unknown; the replay could not reach the provider"
            ) from exc
        except ProviderDefinitelyRejected as exc:
            # Includes ProviderSourceGone: nothing can be applied any more.
            self.repository.transition_execution(
                execution.approval_id,
                expected=frozenset({execution.state}),
                state=ExecutionState.FAILED,
                now=self.now(),
                error_class=type(exc).__name__,
            )
            raise
        except Exception as exc:
            self._record_inconclusive(execution, type(exc).__name__)
            raise
        confirmed = self.repository.transition_execution(
            execution.approval_id,
            expected=frozenset({execution.state}),
            state=ExecutionState.CONFIRMED,
            now=self.now(),
            provider_object_id=self._provider_object_id(safe_result),
            provider_result=safe_result,
        )
        return self._execution_result(confirmed, replayed=True)

    def _may_replay(
        self,
        execution: ActionExecution,
        payload: dict,
        *,
        replay_allowed: bool,
        fence: SideEffectFence | None,
        lease: LeaseToken | None,
        effect: SideEffect | None,
    ) -> bool:
        """Replay only replay-safe payloads, only where the operator allows it.

        A reconcile sweep covers every kind read-only; re-issuing is a
        provider write, so it must pass both the dispatcher's enabled-kind
        gate (``replay_allowed``) and the side-effect fence (a trash row is
        reconciled but never replayed while trash actions are toggled off).
        """
        if not (replay_allowed and self._replay_safe(execution.kind, payload)):
            return False
        if fence is None or effect is None:
            return False
        try:
            fence.assert_allowed(effect, lease)
        except FenceRejected:
            return False
        return True

    def _resume_execution(
        self,
        execution: ActionExecution,
        payload: dict,
        executor: ApprovedActionExecutor | Callable[[dict, str], dict],
        now: dt.datetime,
        *,
        replay_allowed: bool = True,
        fence: SideEffectFence | None = None,
        lease: LeaseToken | None = None,
        effect: SideEffect | None = None,
    ) -> dict:
        if execution.state is ExecutionState.RETRYABLE:
            raise ApprovalError(
                "APPROVAL_CLOSED_BEFORE_PROVIDER_REACHED: the provider was never reached "
                "and the approval was revoked or lapsed; a new draft is needed"
            )
        if execution.state is ExecutionState.CONFIRMED:
            return self._refresh_confirmation(execution, payload, executor)
        if execution.state is ExecutionState.FAILED:
            raise ApprovalError("provider definitely rejected this consumed approval")
        if execution.error_class == ProviderPartialOutcome.__name__:
            self._record_inconclusive(execution, execution.error_class)
            raise ApprovalError(
                "provider reported a partial outcome; the side effect was not replayed"
            )
        if (
            execution.state is ExecutionState.ATTEMPTING
            and now - execution.updated_at < self.stale_execution_after
        ):
            raise ApprovalError("approved action execution is already in progress")
        reconcile = getattr(executor, "reconcile", None)
        if not callable(reconcile):
            raise ApprovalError("approved action outcome is unknown and cannot be replayed")
        try:
            result = reconcile(copy.deepcopy(payload), execution.idempotency_key)
        except ProviderNotAttempted as exc:
            # Reconciliation is read-only; an unreachable provider proves nothing
            # about the earlier attempt, so the outcome stays unknown.
            self._record_inconclusive(execution, "ReconciliationUnavailable", give_up=False)
            raise ApprovalError(
                "provider outcome remains unknown; reconciliation could not reach the "
                "provider and the side effect was not replayed"
            ) from exc
        except ProviderSourceGone as exc:
            # The message is gone everywhere; nothing can ever be applied.
            self.repository.transition_execution(
                execution.approval_id,
                expected=frozenset({execution.state}),
                state=ExecutionState.FAILED,
                now=self.now(),
                error_class=type(exc).__name__,
            )
            raise
        except ProviderProvedNotApplied as exc:
            # Proof that the approved effect is absent. An idempotent
            # operation is simply re-issued; SEND and copy-preserve end final.
            if self._may_replay(
                execution,
                payload,
                replay_allowed=replay_allowed,
                fence=fence,
                lease=lease,
                effect=effect,
            ):
                return self._replay_execution(execution, payload, executor)
            self.repository.transition_execution(
                execution.approval_id,
                expected=frozenset({execution.state}),
                state=ExecutionState.FAILED,
                now=self.now(),
                error_class=type(exc).__name__,
            )
            raise
        except ProviderDefinitelyRejected:
            # A read-only identity check failed (UIDVALIDITY or Message-ID changed).
            # Re-reading can never prove the outcome, so end the row now rather
            # than polling for UNKNOWN_GIVE_UP_AFTER and blocking the message.
            self.repository.transition_execution(
                execution.approval_id,
                expected=frozenset({execution.state}),
                state=ExecutionState.FAILED,
                now=self.now(),
                provider_object_id=execution.provider_object_id,
                provider_result=execution.provider_result,
                error_class=OUTCOME_UNVERIFIED,
            )
            raise
        except Exception as exc:
            self._record_inconclusive(execution, type(exc).__name__)
            raise
        if result is None:
            # Reconciliation proved nothing either way. Re-issuing an
            # idempotent operation resolves it; the executor reports an
            # already-applied effect as success.
            if self._may_replay(
                execution,
                payload,
                replay_allowed=replay_allowed,
                fence=fence,
                lease=lease,
                effect=effect,
            ):
                return self._replay_execution(execution, payload, executor)
            self._record_inconclusive(execution, "ReconciliationInconclusive")
            raise ApprovalError(
                "provider outcome remains unknown; the side effect was not replayed"
            )
        safe_result = self._safe_provider_result(result)
        confirmed = self.repository.transition_execution(
            execution.approval_id,
            expected=frozenset({execution.state}),
            state=ExecutionState.CONFIRMED,
            now=self.now(),
            provider_object_id=self._provider_object_id(safe_result),
            provider_result=safe_result,
        )
        return self._execution_result(confirmed, replayed=True)

    def _refresh_confirmation(
        self,
        execution: ActionExecution,
        payload: dict,
        executor: ApprovedActionExecutor | Callable[[dict, str], dict],
    ) -> dict:
        provider_result = execution.provider_result or {}
        if not (
            provider_result.get("sent_copy_verified") is False
            or provider_result.get("verified") is False
        ):
            return self._execution_result(execution, replayed=True)
        reconcile = getattr(executor, "reconcile", None)
        if not callable(reconcile):
            return self._execution_result(execution, replayed=True)
        try:
            result = reconcile(copy.deepcopy(payload), execution.idempotency_key)
            if result is None:
                return self._execution_result(execution, replayed=True)
            safe_result = self._safe_provider_result(result)
            refreshed = self.repository.transition_execution(
                execution.approval_id,
                expected=frozenset({ExecutionState.CONFIRMED}),
                state=ExecutionState.CONFIRMED,
                now=self.now(),
                provider_object_id=self._provider_object_id(safe_result),
                provider_result=safe_result,
            )
        except Exception:
            # The original provider acknowledgement remains authoritative.
            # A confirmation refresh is read-only and never replays the write.
            return self._execution_result(execution, replayed=True)
        return self._execution_result(refreshed, replayed=True)

    @staticmethod
    def _execute_provider(
        executor: ApprovedActionExecutor | Callable[[dict, str], dict],
        payload: dict,
        idempotency_key: str,
    ) -> dict:
        execute = getattr(executor, "execute", None)
        result = (
            execute(copy.deepcopy(payload), idempotency_key)
            if callable(execute)
            else executor(copy.deepcopy(payload), idempotency_key)
        )
        if not isinstance(result, dict):
            raise RuntimeError("provider executor returned a malformed result")
        return result

    @staticmethod
    def _safe_provider_result(result: dict) -> dict:
        allowed = {
            "status",
            "operation",
            "account",
            "provider_object_id",
            "message_id",
            "stable_message_id",
            "source_folder",
            "destination",
            "source_uid",
            "destination_uid",
            "uid_validity",
            "flag",
            "enabled",
            "verified",
            "reconciled",
            "already_applied",
            "sent_copy_verified",
            "sent_copy_state",
            "source_preserved",
            "source_seen",
            "degraded_copy",
            "strategy",
        }
        unexpected = set(result) - allowed
        if unexpected:
            raise RuntimeError("provider executor returned unsafe result fields")
        safe: dict[str, str | int | bool | None] = {}
        for key, value in result.items():
            if value is not None and not isinstance(value, (str, int, bool)):
                raise RuntimeError("provider executor result contains a non-scalar value")
            safe[key] = value
        return safe

    @staticmethod
    def _provider_object_id(result: dict) -> str | None:
        value = result.get("provider_object_id") or result.get("message_id")
        return str(value) if value else None

    @staticmethod
    def _execution_result(execution: ActionExecution, *, replayed: bool) -> dict:
        return {
            "action_id": execution.action_id,
            "state": execution.state.value,
            "replayed": replayed,
            **copy.deepcopy(execution.provider_result or {}),
        }

    def _reject_receive_only(self, payload: dict) -> None:
        if str(payload.get("account") or "") in self.receive_only_accounts:
            raise ApprovalError("account supports receiving and notifications only")

    def _validate_payload(self, kind: IntentKind, payload: dict) -> None:
        self._reject_receive_only(payload)
        if kind is IntentKind.SEND:
            if (
                not payload.get("account")
                or not payload.get("from")
                or not payload.get("to")
                or not payload.get("subject")
                or not payload.get("body")
                or not payload.get("message_id")
                or not payload.get("date")
            ):
                raise ApprovalError(
                    "send draft requires account, from, to, subject, body, date, and message id"
                )
        elif kind in {IntentKind.ARCHIVE, IntentKind.MOVE, IntentKind.TRASH}:
            required = (
                "account",
                "stable_message_id",
                "source_folder",
                "source_uid",
                "source_uid_validity",
            )
            if any(not payload.get(field) for field in required):
                raise ApprovalError("mail organization draft lacks immutable source identity")
            if not payload.get("provider_message_id") and not payload.get("raw_body_sha256"):
                raise ApprovalError("mail organization draft lacks a provider identity")
            destination = str(payload.get("destination") or "").strip()
            account = self.accounts.get(str(payload.get("account")))
            if kind is IntentKind.TRASH:
                if account is None or destination.casefold() != account.trash_folder.casefold():
                    raise ApprovalError(
                        "mail Trash destination does not match account configuration"
                    )
                if payload.get("operation") != "trash":
                    raise ApprovalError("mail Trash operation is malformed")
            else:
                if account is None or destination.casefold() not in {
                    folder.casefold() for folder in account.safe_move_folders
                }:
                    raise ApprovalError("mail organization destination is not allowlisted")
                if _forbidden_folder(destination):
                    raise ApprovalError("mail organization destination is permanently forbidden")
            fallback = payload.get("copy_preserve_source_fallback")
            expected_fallback = (
                False if kind is IntentKind.TRASH else account.copy_preserve_source_fallback
            )
            if not isinstance(fallback, bool) or fallback != expected_fallback:
                raise ApprovalError("mail organization strategy is malformed")
            uidplus = payload.get("uidplus_move_fallback", False)
            if (
                not isinstance(uidplus, bool)
                or uidplus != (account.alias in self.uidplus_move_accounts)
                or (uidplus and fallback)
            ):
                raise ApprovalError("mail organization strategy is malformed")
        elif kind is IntentKind.MARK:
            required = (
                "account",
                "stable_message_id",
                "source_folder",
                "source_uid",
                "source_uid_validity",
                "action",
            )
            if any(not payload.get(field) for field in required):
                raise ApprovalError("mail mark draft lacks immutable source identity")
            if not payload.get("provider_message_id") and not payload.get("raw_body_sha256"):
                raise ApprovalError("mail mark draft lacks a provider identity")
            # Fail closed at prepare like the other kinds do: an unknown
            # account otherwise burns the approval at execute time.
            if self.accounts.get(str(payload.get("account"))) is None:
                raise ApprovalError("mail mark account is not configured")
            if payload.get("action") not in {"seen", "unseen", "flag", "unflag"}:
                raise ApprovalError("mail mark action is not allowlisted")


_FORBIDDEN_FOLDER = re.compile(
    r"(^|/)(trash|bin|deleted(?: items| messages)?|junk(?: e-mail| email)?|spam)(/|$)",
    re.I,
)


def _forbidden_folder(value: str) -> bool:
    return bool(_FORBIDDEN_FOLDER.search(value.strip())) or value.strip().casefold() in {
        "\\deleted",
        "expunge",
    }
