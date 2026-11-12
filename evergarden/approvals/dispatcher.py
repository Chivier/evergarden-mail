from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from fastapi.concurrency import run_in_threadpool

from evergarden.approvals.models import Draft, IntentKind
from evergarden.approvals.service import (
    UNKNOWN_GIVE_UP_AFTER,
    UNKNOWN_RECONCILE_INTERVAL,
    ApprovalService,
)
from evergarden.config import Settings

LOGGER = logging.getLogger(__name__)
RECONCILE_EVERY_SECONDS = 60.0
# One sweep stops starting new rows after this long; the next sweep continues.
RECONCILE_BUDGET_SECONDS = 50.0
BUSY_POLL_SECONDS = 0.2
IDLE_POLL_SECONDS = 2.0
# Default mailboxes executed at the same time (``approval_dispatch_parallel``).
# Each worker holds one provider connection and at most one message body, so
# this bounds memory and provider connections.
DEFAULT_PARALLEL_MAILBOXES = 4
# Ready approvals examined per scan; bounds the drafts decrypted at once.
SCAN_ROWS = 400
SCAN_PAGE = 100
# Item state when the ledger could not be read after an execution error.
LOOKUP_FAILED = "lookup_failed"
# States that mean no provider progress; they never trigger busy polling.
NO_PROGRESS_STATES = frozenset({"blocked", "deferred", LOOKUP_FAILED})
# States that leave a message's outcome open for the rest of a scan.
UNRESOLVED_STATES = frozenset({"unknown", "attempting", LOOKUP_FAILED})


def approval_dispatch_kinds(settings: Settings) -> frozenset[IntentKind]:
    """Return the intent kinds this host may execute for human approvals."""
    if not (settings.approval_dispatch_enabled and settings.mode == "production"):
        return frozenset()
    kinds = {IntentKind.SEND, IntentKind.ARCHIVE, IntentKind.MOVE, IntentKind.MARK}
    if settings.trash_actions_enabled:
        kinds.add(IntentKind.TRASH)
    return frozenset(kinds)


class ApprovalDispatcher:
    """Use the committed approval and action ledgers as a durable work queue.

    Human approvals of every enabled kind are executed here; policy approvals
    stay with the client that prepared them. No approval is created or extended
    here. The executor owns writer leases, atomic claims and provider identity
    checks. Stale or uncertain ledger rows of any approval source are
    reconciled read-only first; a replay-safe operation (mark, native move)
    whose outcome stays unprovable is re-issued, while SEND and copy-first
    strategies are never replayed.

    Each scan runs up to ``parallel`` mailboxes in parallel, one
    worker and one reused provider connection per mailbox, items of a mailbox in
    order. Reconciliation runs in its own loop and never delays execution.
    """

    def __init__(
        self,
        approvals: ApprovalService,
        execute: Callable[..., dict],
        *,
        kinds: frozenset[IntentKind],
        host: str,
        session: Callable[[], contextlib.AbstractContextManager] = contextlib.nullcontext,
        parallel: int = DEFAULT_PARALLEL_MAILBOXES,
    ):
        self.approvals = approvals
        self.execute = execute
        self.kinds = frozenset(kinds)
        self.host = host
        self.session = session
        self.parallel = max(1, parallel)
        self.stopping = threading.Event()
        self.last_scan_at: str | None = None
        self.last_error_class: str | None = None
        self.last_item_error_class: str | None = None
        self.last_result: dict[str, int] = {}
        self.last_attempted = 0
        self._lock = threading.Lock()
        # Serializes heartbeat writes without blocking workers on the database.
        self._write_lock = threading.Lock()
        # Latest dispatch and reconciliation counts; the heartbeat shows both.
        self._parts: dict[str, dict[str, int]] = {"dispatch": {}, "reconcile": {}}

    def _run_item(self, approval_id: str, draft: Draft) -> str:
        """Execute one approval and return its ledger state, or ``deferred``."""
        try:
            execution = self.execute(
                approval_id=approval_id,
                draft_id=draft.draft_id,
                current_payload=draft.payload,
                expected_kind=draft.kind,
                # Reconciliation covers every kind read-only; only kinds this
                # host dispatches may be actively replayed.
                replay_allowed=draft.kind in self.kinds,
            )
            return str(execution["state"]).casefold()
        except Exception as exc:
            self.last_item_error_class = type(exc).__name__
            try:
                claimed = self.approvals.repository.get_execution_for_approval(approval_id)
            except Exception as lookup:
                # The attempt may have reached the provider; treat the message
                # as unresolved for the rest of this scan and let the next one,
                # or reconciliation, read the ledger again.
                LOGGER.warning(
                    "approval_dispatch kind=%s state=%s error_class=%s lookup_error_class=%s",
                    draft.kind.value,
                    LOOKUP_FAILED,
                    type(exc).__name__,
                    type(lookup).__name__,
                )
                return LOOKUP_FAILED
            # Fence, lease or validation: nothing was claimed, so the approval
            # stays ready for a later scan.
            state = claimed.state.value.casefold() if claimed else "deferred"
            # Never log exception text, mail contents, hashes or credentials.
            LOGGER.warning(
                "approval_dispatch kind=%s state=%s error_class=%s",
                draft.kind.value,
                state,
                type(exc).__name__,
            )
            return state

    def _collect(
        self, limit: int, result: dict[str, int]
    ) -> tuple[dict[str, list[tuple[str, Draft]]], set[str]]:
        """Group ready approvals by mailbox, up to ``limit`` each, skipping blocked ones."""
        repository = self.approvals.repository
        groups: dict[str, list[tuple[str, Draft]]] = {}
        unresolved: set[str] | None = None
        scanned = 0
        while scanned < SCAN_ROWS and not self.stopping.is_set():
            page = repository.ready_human_approvals(
                self.approvals.now(),
                kinds=self.kinds,
                limit=min(SCAN_PAGE, SCAN_ROWS - scanned),
                offset=scanned,
            )
            if not page:
                break
            scanned += len(page)
            drafts = repository.get_drafts_batch([draft_id for _, draft_id in page])
            for approval_id, draft_id in page:
                draft = drafts.get(draft_id)
                if not isinstance(draft, Draft):
                    # Missing or undecryptable: nothing is claimed; retried later.
                    result["deferred"] = result.get("deferred", 0) + 1
                    continue
                mid = draft.payload.get("stable_message_id")
                if mid:
                    if unresolved is None:
                        unresolved = repository.unresolved_message_ids()
                    if mid in unresolved:
                        # An older uncertain action on the same message must
                        # be reconciled before another one may run.
                        result["blocked"] = result.get("blocked", 0) + 1
                        continue
                group = groups.setdefault(str(draft.payload.get("account") or ""), [])
                if len(group) < limit:
                    group.append((approval_id, draft))
            if sum(len(group) for group in groups.values()) >= limit * self.parallel:
                break
        return groups, unresolved or set()

    def run_once(self, *, limit: int = 10) -> dict[str, int]:
        """Run up to ``limit`` ready approvals per mailbox, mailboxes in parallel."""
        result: dict[str, int] = {}
        groups, unresolved = self._collect(limit, result)
        attempted = 0

        def work(items: list[tuple[str, Draft]]) -> None:
            nonlocal attempted
            uncertain = set(unresolved)
            with self.session():
                for approval_id, draft in items:
                    if self.stopping.is_set():
                        return
                    mid = draft.payload.get("stable_message_id")
                    if mid and mid in uncertain:
                        state = "blocked"
                    else:
                        state = self._run_item(approval_id, draft)
                        if state in UNRESOLVED_STATES and mid:
                            uncertain.add(str(mid))
                    with self._lock:
                        # Busy polling follows real progress only, never a
                        # deferred item that would be retried straight away.
                        if state not in NO_PROGRESS_STATES:
                            attempted += 1
                        result[state] = result.get(state, 0) + 1
                        snapshot = dict(result)
                    # One item can take seconds; keep the liveness signal fresh
                    # so the approval surface does not treat a busy dispatcher as down.
                    self.heartbeat(snapshot, None)

        if groups:
            workers = min(self.parallel, len(groups))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dispatch") as pool:
                for future in [pool.submit(work, items) for items in groups.values()]:
                    # A failed mailbox worker (for example its provider session)
                    # must not discard what the other mailboxes completed.
                    try:
                        future.result()
                    except Exception as exc:
                        self.last_item_error_class = type(exc).__name__
                        with self._lock:
                            result["worker_failed"] = result.get("worker_failed", 0) + 1
                        LOGGER.error(
                            "approval_dispatch worker_failed error_class=%s", type(exc).__name__
                        )
        self.last_attempted = attempted
        if result:
            LOGGER.info("approval_dispatch completed=%s", result)
        return result

    def reconcile_once(self, *, limit: int = 30) -> dict[str, int]:
        """Resolve stale ATTEMPTING and UNKNOWN rows.

        Each row is reconciled read-only first; an unprovable replay-safe
        operation is then re-issued (idempotent retry), while SEND and
        copy-first strategies stay read-only. A row ends CONFIRMED or FAILED
        once the mailbox proves the outcome, or FAILED/OutcomeUnverified after
        ``UNKNOWN_GIVE_UP_AFTER``. Rows of one mailbox share a connection.
        """
        repository = self.approvals.repository
        now = self.approvals.now()
        # The sweep covers every kind — not just the kinds this host currently
        # dispatches — because resolving a row is read-only unless a replay is
        # explicitly allowed (see replay_allowed in _run_item). Otherwise an
        # UNKNOWN row of a disabled kind (e.g. trash toggled off) is never
        # resolved, never hits the give-up deadline, and blocks its message
        # forever.
        rows = repository.reconcilable_executions(
            now,
            kinds=frozenset(IntentKind),
            attempting_before=now - self.approvals.stale_execution_after,
            unknown_before=now - UNKNOWN_RECONCILE_INTERVAL,
            give_up_before=now - UNKNOWN_GIVE_UP_AFTER,
            limit=limit,
        )
        drafts = repository.get_drafts_batch([draft_id for _, draft_id in rows]) if rows else {}
        groups: dict[str, list[tuple[str, Draft]]] = {}
        for approval_id, draft_id in rows:
            draft = drafts.get(draft_id)
            if isinstance(draft, Draft):
                account = str(draft.payload.get("account") or "")
                groups.setdefault(account, []).append((approval_id, draft))
        result: dict[str, int] = {}
        started = time.monotonic()
        for items in groups.values():
            try:
                with self.session():
                    for approval_id, draft in items:
                        if (
                            self.stopping.is_set()
                            or time.monotonic() - started >= RECONCILE_BUDGET_SECONDS
                        ):
                            break
                        state = self._run_item(approval_id, draft)
                        key = {"confirmed": "reconciled", "failed": "reconciled_failed"}.get(
                            state, "reconcile_inconclusive"
                        )
                        result[key] = result.get(key, 0) + 1
                        # A mailbox read can take seconds; keep the liveness check fresh.
                        self.heartbeat(dict(result), None, part="reconcile")
            except Exception as exc:
                # One mailbox failing must not stop reconciliation of the others.
                self.last_item_error_class = type(exc).__name__
                result["worker_failed"] = result.get("worker_failed", 0) + 1
                LOGGER.error(
                    "approval_dispatch reconcile_worker_failed error_class=%s",
                    type(exc).__name__,
                )
        if result:
            LOGGER.info("approval_dispatch reconcile=%s", result)
        return result

    def heartbeat(
        self,
        result: dict[str, int],
        error_class: str | None,
        *,
        part: str = "dispatch",
        wait: bool = False,
    ) -> None:
        """Record liveness; a failed write is logged and never stops dispatch.

        The shared lock only guards the in-memory state. The database write
        happens outside it, one at a time: a worker whose heartbeat finds
        another write in flight skips its own (that write keeps liveness fresh)
        instead of waiting on the database. ``wait`` is for the end-of-scan
        heartbeat, which must be recorded.
        """
        with self._lock:
            self._parts[part] = dict(result)
            if part == "dispatch":
                self.last_error_class = error_class
        if not self._write_lock.acquire(blocking=wait):
            return
        try:
            with self._lock:
                # Sum shared keys (both parts can report worker_failed) instead
                # of letting one part overwrite the other's count.
                merged = dict(self._parts["dispatch"])
                for key, value in self._parts["reconcile"].items():
                    merged[key] = merged.get(key, 0) + value
                scanned_at = self.approvals.now()
                self.last_scan_at = scanned_at.isoformat()
                self.last_result = merged
                status = {
                    "host": self.host,
                    "kinds": sorted(kind.value for kind in self.kinds),
                    "last_scan_at": scanned_at,
                    "last_error_class": self.last_error_class,
                    "last_item_error_class": self.last_item_error_class,
                    "last_result": merged,
                }
            try:
                self.approvals.repository.record_dispatcher_status(**status)
            except Exception as exc:
                LOGGER.error(
                    "approval_dispatch heartbeat_failed error_class=%s", type(exc).__name__
                )
        finally:
            self._write_lock.release()

    async def _reconcile_loop(self, stop: asyncio.Event) -> None:
        while not stop.is_set() and not self.stopping.is_set():
            try:
                await run_in_threadpool(self.reconcile_once)
            except Exception as exc:
                LOGGER.error(
                    "approval_dispatch reconcile_failed error_class=%s", type(exc).__name__
                )
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=RECONCILE_EVERY_SECONDS)

    async def run(self, stop: asyncio.Event) -> None:
        # The reconciler stops with this loop, whichever stop signal ended it.
        halt = asyncio.Event()
        reconciler = asyncio.create_task(self._reconcile_loop(halt))
        try:
            while not stop.is_set() and not self.stopping.is_set():
                result: dict[str, int] = {}
                error_class = None
                try:
                    result = await run_in_threadpool(self.run_once)
                except Exception as exc:
                    error_class = type(exc).__name__
                    self.last_attempted = 0
                    LOGGER.error("approval_dispatch scan_failed error_class=%s", error_class)
                await run_in_threadpool(
                    functools.partial(self.heartbeat, result, error_class, wait=True)
                )
                delay = BUSY_POLL_SECONDS if self.last_attempted else IDLE_POLL_SECONDS
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=delay)
        finally:
            halt.set()
            await reconciler
