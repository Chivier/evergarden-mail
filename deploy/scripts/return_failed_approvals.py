#!/usr/bin/env python3
"""Return still-actionable failures as new, unapproved drafts; never change mail.

Run in the production MCP environment. The default is a read-only preview;
--apply creates drafts after live identity and non-application checks. Original
approvals/executions remain untouched. Repeated runs do not duplicate returns.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import uuid
from contextlib import closing

from psycopg.rows import dict_row

from apps.mcp.main import _default_runtime
from evergarden import database
from evergarden.approvals.models import Draft, IntentKind
from evergarden.approvals.service import _canonical_hash
from evergarden.archive.sqlite_archive import ArchiveWriter, open_readonly
from evergarden.config import Settings
from evergarden.mail.actions import _FLAGS
from evergarden.mail.sync import parse_message

RECOVERABLE = frozenset(
    {"ProviderDefinitelyRejected", "ProviderProvedNotApplied", "ApprovalLapsedBeforeRetry"}
)


class ReadOnlyIMAP:
    """Enforce EXAMINE, SEARCH and BODY.PEEK at the provider boundary."""

    def __init__(self, client):
        self.client = client

    def select(self, folder, *, readonly):
        return self.client.select(folder, readonly=True)

    def response(self, name):
        return self.client.response(name)

    def uid(self, command, *arguments):
        if command == "FETCH":
            if len(arguments) != 2 or arguments[1] != "(UID FLAGS RFC822.SIZE BODY.PEEK[])":
                raise RuntimeError("recovery allows only non-marking identity fetches")
        elif command != "SEARCH":
            raise RuntimeError("recovery cannot mutate provider mail")
        return self.client.uid(command, *arguments)


def identity(draft):
    return draft.kind, draft.payload.get("account"), draft.payload.get("stable_message_id")


def candidates(rows, drafts, now):
    """Later execution, revocation or a live draft supersedes an old failure."""
    latest = {}
    for row in rows:
        draft = drafts.get(str(row["draft_id"]))
        if draft is None or not draft.payload.get("stable_message_id"):
            continue
        if row["approval_id"] is None and draft.expires_at <= now:
            continue
        key = identity(draft)
        if key not in latest or (draft.created_at, draft.draft_id) > (
            latest[key][0].created_at,
            latest[key][0].draft_id,
        ):
            latest[key] = draft, row
    return [
        (draft, row)
        for draft, row in latest.values()
        if row["state"] == "FAILED"
        and row["error_class"] in RECOVERABLE
        and row["revoked_at"] is None
        and draft.kind in {IntentKind.TRASH, IntentKind.ARCHIVE, IntentKind.MOVE, IntentKind.MARK}
    ]


def prepare_payload(runtime, draft):
    old = draft.payload
    mid = old["stable_message_id"]
    if old["account"] in runtime.receive_only_accounts:
        raise ValueError("receive_only")
    diagnosis = runtime.location_snapshot().state(mid)
    if diagnosis["location_status"] != "valid" or diagnosis.get("reason_code") == (
        "PROVIDER_OUTCOME_UNKNOWN"
    ):
        raise ValueError("location_not_verified")
    arguments = {
        "account": old["account"],
        "stable_message_id": mid,
        "source_folder": old["source_folder"],
    }
    if draft.kind is IntentKind.MARK:
        return runtime._mark_payload({**arguments, "action": old["action"]})
    payload = runtime._organization_payload(
        {**arguments, "destination": old["destination"]}, destination_kind=draft.kind.value
    )
    if payload["destination"].casefold() != old["destination"].casefold():
        raise ValueError("destination_policy_changed")
    return payload


def prove_pending(actions, payload):
    """Require the exact source and prove the intended effect is absent today."""
    with actions._imap(actions._account(payload)) as connection:
        client = ReadOnlyIMAP(connection)
        source = actions._source(client, payload)
        if source is None:
            return False
        if payload["operation"] == "mark":
            flag, enabled = _FLAGS[payload["action"]]
            return (flag in source[1]) is not enabled
        return actions._destination_lacks_copy(client, payload)


def refresh_source_hash(actions, archive, payload):
    """Refresh transport bytes only for a fully equivalent provider variant.

    A stable ID or Message-ID alone cannot establish content identity. Reuse
    the sync verifier's full headers/body/attachment comparison, read-only.
    The old draft/hash is never edited; this hash belongs to the new review.
    """
    with actions._imap(actions._account(payload)) as connection:
        client = ReadOnlyIMAP(connection)
        validity = actions._select(client, payload["source_folder"], readonly=True)
        if validity != payload["source_uid_validity"]:
            raise ValueError("source_uidvalidity_changed")
        fetched = actions._fetch(client, payload["source_uid"])
        if fetched is None:
            raise ValueError("source_missing")
        raw, flags, size = fetched
        raw_hash = hashlib.sha256(raw).hexdigest()
        if raw_hash == payload.get("raw_body_sha256"):
            return
        parsed = parse_message(
            account=payload["account"],
            folder=payload["source_folder"],
            uid=payload["source_uid"],
            raw=raw,
            flags=flags,
            raw_size=size,
        )
        if parsed.stable_id != payload["stable_message_id"]:
            raise ValueError("source_identity_changed")
        for path in archive.paths():
            with closing(open_readonly(path)) as conn:
                row = conn.execute(
                    "SELECT * FROM messages WHERE id=?", (payload["stable_message_id"],)
                ).fetchone()
                if row is None:
                    continue
                if not ArchiveWriter._provider_variant_matches(conn, row, parsed):
                    raise ValueError("source_content_changed")
                payload["raw_body_sha256"] = raw_hash
                payload["recovery_identity_refreshed"] = True
                return
        raise ValueError("source_not_archived")


def run(*, apply=False):
    settings = Settings()
    _, runtime, _ = _default_runtime(settings)
    repository = runtime.approvals.repository
    actions = runtime.organization_capabilities_provider.__self__
    now = dt.datetime.now(dt.UTC)
    # A session lock serializes maintenance runs, including the provider reads.
    with database.connect(settings.database_url, autocommit=True, row_factory=dict_row) as lock:
        lock.execute(
            "SELECT pg_advisory_lock(%s)",
            (database.advisory_key("approval-recovery", "return-failed-v1"),),
        )
        rows = lock.execute(
            "SELECT d.draft_id,a.approval_id,a.revoked_at,l.state,l.error_class "
            "FROM approval_drafts d LEFT JOIN approvals a USING(draft_id) "
            "LEFT JOIN mail_action_ledger l USING(approval_id)"
        ).fetchall()
        drafts = repository.get_drafts_batch([str(row["draft_id"]) for row in rows])
        results = []
        for old, row in candidates(rows, drafts, now):
            new_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"evergarden:failed-return:{old.draft_id}"))
            result = {"original_draft_id": old.draft_id, "kind": old.kind.value}
            if new_id in drafts:
                results.append({**result, "status": "already_returned", "draft_id": new_id})
                continue
            try:
                payload = prepare_payload(runtime, old)
                refresh_source_hash(actions, runtime.archive, payload)
                if not prove_pending(actions, payload):
                    results.append({**result, "status": "not_proved_pending"})
                    continue
                context = runtime.archive.message_context(payload["stable_message_id"])
                payload.update(
                    subject=str(context.get("subject") or ""),
                    sender=str(context.get("sender_email") or ""),
                    date_received=str(context.get("date_received") or ""),
                    recovery_of=old.draft_id,
                    recovery_error=row["error_class"],
                )
                runtime.approvals._validate_payload(old.kind, payload)
                created = dt.datetime.now(dt.UTC)
                draft = Draft(
                    draft_id=new_id,
                    kind=old.kind,
                    payload=payload,
                    payload_hash=_canonical_hash(old.kind, payload),
                    created_by="admin-requested-recovery",
                    created_client="failed-approval-recovery",
                    created_at=created,
                    expires_at=created + dt.timedelta(minutes=60),
                )
                if apply:
                    # Do not call prepare(): policy auto-approval must never apply
                    # to a return that the user explicitly wants to review again.
                    repository.add_draft(draft)
                    database.append_audit_event(
                        settings.database_url,
                        event_type="approval.returned_for_review",
                        actor="admin-requested-recovery",
                        client_id="failed-approval-recovery",
                        outcome="pending_human",
                        metadata={"original_draft_id": old.draft_id, "draft_id": new_id},
                    )
                results.append(
                    {**result, "status": "returned" if apply else "ready", "draft_id": new_id}
                )
            except Exception as exc:
                # Exception messages can contain private provider or mail details.
                results.append({**result, "status": "skipped", "error_class": type(exc).__name__})
        return {"apply": apply, "provider_mutations": 0, "results": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(apply=args.apply), ensure_ascii=False))
