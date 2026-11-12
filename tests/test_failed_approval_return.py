from __future__ import annotations

import dataclasses
import datetime as dt
from types import SimpleNamespace

import pytest

from deploy.scripts.return_failed_approvals import (
    ReadOnlyIMAP,
    candidates,
    prove_pending,
    refresh_source_hash,
)
from evergarden.approvals.models import Actor, IntentKind
from evergarden.approvals.service import ApprovalRepository, ApprovalService
from tests.test_batch_approval import prepare


def test_return_candidates_exclude_uncertain_gone_and_superseded(fixed_now):
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    old = prepare(service)
    failed = {
        "draft_id": old.draft_id,
        "approval_id": "old-approval",
        "revoked_at": None,
        "state": "FAILED",
        "error_class": "ProviderProvedNotApplied",
    }
    assert len(candidates([failed], {old.draft_id: old}, fixed_now)) == 1
    for error in ("ProviderSourceGone", "OutcomeUnverified"):
        assert candidates([{**failed, "error_class": error}], {old.draft_id: old}, fixed_now) == []
    newer = dataclasses.replace(
        old, draft_id="new", created_at=old.created_at + dt.timedelta(seconds=1)
    )
    drafts = {old.draft_id: old, newer.draft_id: newer}
    for state, approval_id, revoked_at in (
        ("CONFIRMED", "new-approval", None),
        ("UNKNOWN", "new-approval", None),
        ("FAILED", "new-approval", fixed_now),
        (None, None, None),
    ):
        row = {
            **failed,
            "draft_id": newer.draft_id,
            "state": state,
            "approval_id": approval_id,
            "revoked_at": revoked_at,
        }
        assert candidates([failed, row], drafts, fixed_now) == []
    # An expired, never-approved preview does not cancel the user's old intent.
    drafts["new"] = dataclasses.replace(newer, expires_at=fixed_now)
    assert len(candidates([failed, row], drafts, fixed_now)) == 1


def test_recovery_provider_guard_forces_readonly_and_rejects_mutations():
    calls = []
    client = ReadOnlyIMAP(
        SimpleNamespace(
            select=lambda *args, **kwargs: calls.append((args, kwargs)),
            uid=lambda *args: calls.append(args),
        )
    )
    client.select('"INBOX"', readonly=False)
    assert calls[-1][1] == {"readonly": True}
    client.uid("FETCH", "1", "(UID FLAGS RFC822.SIZE BODY.PEEK[])")
    client.uid("SEARCH", None, "ALL")
    for command, args in (
        ("STORE", ("1", "+FLAGS", "Seen")),
        ("MOVE", ("1", "Trash")),
        ("EXPUNGE", ("1",)),
        ("FETCH", ("1", "(BODY[])")),
    ):
        with pytest.raises(RuntimeError):
            client.uid(command, *args)


def test_mark_already_applied_is_not_returned():
    from contextlib import nullcontext

    payload = {"operation": "mark", "action": "seen"}
    actions = SimpleNamespace(
        _account=lambda _: None,
        _imap=lambda _: nullcontext(object()),
        _source=lambda *_: (b"raw", ("\\Seen",), 3),
    )
    assert not prove_pending(actions, payload)
    actions._source = lambda *_: (b"raw", (), 3)
    assert prove_pending(actions, payload)
    actions._source = lambda *_: None
    assert not prove_pending(actions, payload)


def test_other_pending_appears_in_todo_and_requires_new_human_approval(fixed_now):
    service = ApprovalService(ApprovalRepository(), now=lambda: fixed_now)
    trash = prepare(service)
    archive = prepare(service, IntentKind.ARCHIVE)
    expired = prepare(service, IntentKind.ARCHIVE, lifetime=dt.timedelta(seconds=-1))
    page = service.pending_trash_page(limit=50, offset=0)
    assert [item["draft_id"] for item in page["drafts"]] == [trash.draft_id]
    assert [item["draft_id"] for item in page["other_drafts"]] == [archive.draft_id]
    assert page["other_total"] == 1
    assert expired.draft_id not in [item["draft_id"] for item in page["other_drafts"]]
    assert service.approval_for(archive.draft_id) is None
    service.approve(
        draft_id=archive.draft_id,
        payload_hash=archive.payload_hash,
        actor=Actor("admin", "approval-ui", "approval-ui", True),
    )
    assert service.pending_trash_page(limit=50, offset=0)["other_drafts"] == []


def test_refresh_accepts_transport_variant_but_rejects_changed_body(tmp_path):
    import hashlib
    from contextlib import nullcontext

    from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter
    from evergarden.mail.sync import parse_message

    raw = (
        b"From: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\n"
        b"Subject: Review\r\nMessage-ID: <recovery@example.test>\r\n"
        b"Date: Sun, 25 Oct 2026 12:00:00 +0000\r\n\r\nSame body\r\n"
    )
    record = parse_message(
        account="gmail", folder="INBOX", uid=7, raw=raw, flags=(), raw_size=len(raw)
    )
    archive = tmp_path / "archive"
    ArchiveWriter(archive).upsert(record, uid_validity="777")
    reader = ArchiveReader(archive)
    variant = b"Received: from provider.example.test\r\n" + raw
    actions = SimpleNamespace(
        _account=lambda _: None,
        _imap=lambda _: nullcontext(object()),
        _select=lambda *_args, **_kwargs: "777",
        _fetch=lambda *_: (variant, (), len(variant)),
    )
    payload = {
        "account": "gmail",
        "source_folder": "INBOX",
        "source_uid": 7,
        "source_uid_validity": "777",
        "stable_message_id": record.stable_id,
        "raw_body_sha256": record.raw_body_sha256,
    }
    refresh_source_hash(actions, reader, payload)
    assert payload["raw_body_sha256"] == hashlib.sha256(variant).hexdigest()
    assert reader.message_context(record.stable_id)["raw_body_sha256"] == record.raw_body_sha256
    changed = raw.replace(b"Same body", b"Different body")
    actions._fetch = lambda *_: (changed, (), len(changed))
    with pytest.raises(ValueError, match="content_changed"):
        refresh_source_hash(actions, reader, payload)
