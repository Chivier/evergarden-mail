from __future__ import annotations

import dataclasses
import datetime as dt
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from account_fixtures import TEST_ACCOUNTS
from conftest import message_record
from fastapi.testclient import TestClient
from test_mail_admin_ui import FakeGateway, _admin_files, _login, _private
from test_mcp_contract import _client, _tool_call, _tool_value

from apps.mail_ui.main import create_app
from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter, open_writer
from evergarden.config import Settings
from evergarden.mail.diagnostics import LocationSnapshot
from evergarden.mail.feedback import FeedbackStore
from evergarden.mail.sync import ReadOnlyMailboxSync

MID = "a" * 24


def located(tmp_path):
    writer = ArchiveWriter(tmp_path)
    writer.upsert(message_record(MID), uid_validity="1")
    writer.set_sync_state("gmail", "INBOX", "1", 1)
    return writer, ArchiveReader(tmp_path)


def test_diagnostics_read_one_committed_snapshot_during_a_sync(tmp_path, monkeypatch):
    from evergarden.mail import diagnostics

    writer, reader = located(tmp_path)
    original_open = diagnostics.open_readonly
    changed = False

    class ConcurrentRead:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *args):
            nonlocal changed
            if not changed and "FROM messages" in sql:
                changed = True
                with open_writer(writer.hot_path) as other:
                    other.execute("BEGIN IMMEDIATE")
                    other.execute("UPDATE shadow_sync_state SET uid_validity='2'")
                    other.execute("UPDATE message_locations SET uid_validity='2'")
                    other.execute("UPDATE provider_uid_observations SET uid_validity='2'")
                    other.execute("UPDATE messages SET flags='[\"\\\\Seen\"]'")
                    other.execute("UPDATE message_locations SET flags='[\"\\\\Seen\"]'")
            return self.connection.execute(sql, *args)

        def close(self):
            self.connection.close()

    monkeypatch.setattr(diagnostics, "open_readonly", lambda p: ConcurrentRead(original_open(p)))
    snapshot = LocationSnapshot(reader)
    assert snapshot.state(MID)["location_status"] == "valid"
    assert snapshot.messages[MID]["flags"] == "[]"
    assert LocationSnapshot(reader).state(MID)["location_status"] == "valid"


def test_older_sync_failure_cannot_replace_a_newer_success(tmp_path):
    writer, reader = located(tmp_path)
    writer.record_sync_attempt(
        "gmail", "INBOX", "new-run", "ok", None, started_at="2026-10-11T10:00:02+00:00"
    )
    writer.record_sync_attempt(
        "gmail",
        "INBOX",
        "old-run",
        "failed",
        "AUTHENTICATION_FAILED",
        started_at="2026-10-11T10:00:01+00:00",
    )
    assert LocationSnapshot(reader).attempts[("gmail", "inbox")]["sync_run_id"] == "new-run"


def test_evidence_cache_is_shared_until_any_shard_commits(tmp_path, monkeypatch):
    from evergarden.mail import diagnostics

    writer, reader = located(tmp_path)
    builds = 0
    original = diagnostics.LocationEvidence.__init__

    def counted(self, archive):
        nonlocal builds
        builds += 1
        original(self, archive)

    # A first read creates the -wal/-shm files, as in a long-running archive.
    LocationSnapshot(reader)
    monkeypatch.setattr(diagnostics.LocationEvidence, "__init__", counted)
    cache = diagnostics.LocationEvidenceCache(reader)
    with ThreadPoolExecutor(max_workers=8) as pool:
        shared = set(map(id, pool.map(lambda _: cache.get(), range(8))))
    assert len(shared) == 1 and builds == 1

    writer.set_sync_state("gmail", "INBOX", "2", 1)
    evidence = cache.get()
    assert builds == 2
    snapshot = LocationSnapshot(reader, evidence=evidence)
    assert snapshot.state(MID)["location_status"] == "uidvalidity_changed"
    assert cache.get() is evidence

    cache.max_age_seconds = 0
    assert cache.get() is not evidence


def test_confirmed_move_immediately_uses_destination_flags_in_counts(tmp_path):
    writer, reader = located(tmp_path)
    writer.confirm_move(
        MID,
        account="gmail",
        source="INBOX",
        destination="Archive",
        destination_uid=9,
        destination_uid_validity="2",
        destination_flags=("\\Seen",),
    )
    writer.set_sync_state("gmail", "Archive", "2", 9)
    snapshot = LocationSnapshot(reader)
    assert snapshot.state(MID)["location_status"] == "valid"
    assert snapshot.counts(unread_only=True)["count"] == 0
    assert reader.message_context(MID)["flags"] == ["\\Seen"]


def test_missing_hot_location_does_not_resurrect_shard_and_diagnostics_are_readonly(tmp_path):
    writer, reader = located(tmp_path)
    writer.rollover_copy_only(scheduled_slot="test", cutoff=dt.date(2027, 1, 1))
    with open_writer(writer.hot_path) as conn:
        conn.execute("DELETE FROM messages WHERE id=?", (MID,))
        conn.execute("DELETE FROM message_locations WHERE stable_id=?", (MID,))
        conn.execute("DELETE FROM provider_uid_observations WHERE stable_id=?", (MID,))
    before = {p.name: p.read_bytes() for p in reader.paths()}
    value = LocationSnapshot(reader).diagnose(MID)
    assert value["location_status"] == "missing"
    assert value["actionable"] is False
    assert value["reason_code"] == "NO_ACTIVE_PROVIDER_LOCATION"
    assert value["provider_location_exists"] is False
    assert value["provider_location_history_exists"] is True
    assert value["provider_queried"] is False
    assert value["feedback_url"].startswith("/feedback?message_id=")
    assert value["request_id"]
    assert {p.name: p.read_bytes() for p in reader.paths()} == before
    assert not (tmp_path / "location-feedback.db").exists()


@pytest.mark.parametrize(
    "case, expected, reason",
    [
        ("valid", "valid", None),
        ("missing", "missing", "NO_ACTIVE_PROVIDER_LOCATION"),
        ("epoch", "uidvalidity_changed", "UIDVALIDITY_CHANGED"),
        ("auth", "auth_failed", "AUTHENTICATION_FAILED"),
        ("failed_sync", "unverified", "SYNC_FAILED"),
        ("stale", "unverified", "PROVIDER_VERIFICATION_STALE"),
        ("identity", "unverified", "PROVIDER_IDENTITY_MISMATCH"),
        ("ambiguous", "ambiguous", "AMBIGUOUS_PROVIDER_LOCATIONS"),
    ],
)
def test_location_status_requires_specific_evidence(tmp_path, case, expected, reason):
    writer, reader = located(tmp_path)
    now = dt.datetime.now(dt.UTC)
    if case == "missing":
        writer.reconcile_folder_snapshot("gmail", "INBOX", "1", set())
    if case == "epoch":
        writer.set_sync_state("gmail", "INBOX", "2", 1)
    if case in {"auth", "failed_sync"}:
        writer.record_sync_attempt(
            "gmail",
            "INBOX",
            "run-1",
            "failed",
            "AUTHENTICATION_FAILED" if case == "auth" else "SYNC_FAILED",
        )
    if case == "stale":
        now += dt.timedelta(hours=25)
    if case == "identity":
        with open_writer(writer.hot_path) as conn:
            conn.execute("UPDATE message_locations SET raw_body_sha256='different'")
    if case == "ambiguous":
        writer.upsert(message_record(MID, uid=2), uid_validity="1")
    value = LocationSnapshot(reader, now=now).diagnose(MID)
    assert value["location_status"] == expected
    assert value["reason_code"] == reason
    assert value["actionable"] is (case == "valid")
    if case == "missing":
        assert (
            value["provider_locations"][0]["deactivation_reason"]
            == "UID_ABSENT_FROM_PROVIDER_SNAPSHOT"
        )
        assert value["provider_locations"][0]["deactivated_at"]
    assert "body_text" not in json.dumps(value)
    assert "ordinary body" not in json.dumps(value)


def test_unlocated_import_is_unverified_without_provider_snapshot(tmp_path):
    writer = ArchiveWriter(tmp_path)
    writer.import_unlocated_records([message_record(MID)])
    assert LocationSnapshot(ArchiveReader(tmp_path)).state(MID)["location_status"] == "unverified"
    writer.set_sync_state("gmail", "INBOX", "1", 1)
    value = LocationSnapshot(ArchiveReader(tmp_path)).state(MID)
    assert value["location_status"] == "unverified"
    assert value["provider_present"] is False
    assert value["historical_copy_only"] is True


def test_inactive_locator_history_is_not_a_current_provider_location(tmp_path):
    writer, reader = located(tmp_path)
    writer.reconcile_folder_snapshot("gmail", "INBOX", "1", set())
    snapshot = LocationSnapshot(reader, executions={MID: [{"state": "UNKNOWN"}]})
    value = snapshot.diagnose(MID)
    assert value["provider_location_exists"] is False
    assert value["provider_location_history_exists"] is True
    assert value["actionable"] is False
    counts = snapshot.counts(inbox_only=True, unread_only=True)
    assert counts["indexed_count"] == 1
    assert counts["provider_present_count"] == 0
    assert counts["historical_copy_only_count"] == 1
    assert counts["unknown_outcome_count"] == 1


def test_confirmed_move_is_distinct_from_missing_and_other_matches_stay_ambiguous(tmp_path):
    writer, reader = located(tmp_path)
    writer.confirm_move(
        MID,
        account="gmail",
        source="INBOX",
        destination="Archive",
        destination_uid=9,
        destination_uid_validity="2",
    )
    # Stale indexed folder, with an explicit provider-confirmed move event.
    with open_writer(writer.hot_path) as conn:
        conn.execute("UPDATE messages SET folder='INBOX',uid=1 WHERE id=?", (MID,))
    value = LocationSnapshot(reader).diagnose(MID)
    assert value["location_status"] == "moved_confirmed"
    assert value["other_folder_matches"][0]["folder"] == "Archive"
    writer.set_sync_state("gmail", "Archive", "2", 9)
    verified_destination = LocationSnapshot(reader).diagnose(MID)
    assert verified_destination["provider_present"] is False
    assert verified_destination["provider_location_exists"] is True
    writer.upsert(message_record(MID, folder="Other", uid=3), uid_validity="3")
    with open_writer(writer.hot_path) as conn:
        conn.execute("UPDATE messages SET folder='INBOX',uid=1 WHERE id=?", (MID,))
    value = LocationSnapshot(reader).diagnose(MID)
    assert value["match_status"] == "ambiguous"
    assert len(value["other_folder_matches"]) == 2
    assert value["actionable"] is False


def test_counts_filters_and_keyset_pages_deduplicate_before_filtering(tmp_path):
    writer, reader = located(tmp_path)
    for letter, uid in [("b", 2), ("c", 3), ("d", 4)]:
        writer.upsert(message_record(letter * 24, uid=uid), uid_validity="1")
    writer.rollover_copy_only(scheduled_slot="test", cutoff=dt.date(2027, 1, 1))
    writer.upsert(message_record("d" * 24, uid=4, flags=("\\Seen",)), uid_validity="1")
    writer.reconcile_folder_snapshot("gmail", "INBOX", "1", {1, 3, 4})
    snapshot = LocationSnapshot(reader)
    counts = snapshot.counts(inbox_only=True, unread_only=True)
    assert counts["count"] == 3
    assert counts["actionable_count"] == 2
    assert counts["location_anomaly_count"] == 1
    assert counts["unverified_count"] == 0
    assert len(snapshot.filtered(actionable_only=True, unread_only=True)) == 2
    assert [x["id"] for x in snapshot.filtered(location_status="missing")] == ["b" * 24]
    first = snapshot.page(limit=1, unread_only=True)
    assert first["items"][0]["id"] == "c" * 24
    # A new item before the cursor must not shift the next page or duplicate rows.
    writer.upsert(message_record("f" * 24, uid=8), uid_validity="1")
    second = LocationSnapshot(reader).page(limit=1, cursor=first["next_cursor"], unread_only=True)
    assert second["items"][0]["id"] == "b" * 24
    third = snapshot.page(limit=1, cursor=second["next_cursor"], unread_only=True)
    assert third["items"][0]["id"] == MID
    assert third["next_cursor"] is None
    with pytest.raises(ValueError, match="cursor"):
        snapshot.page(cursor=first["next_cursor"], unread_only=False)
    with pytest.raises(ValueError, match="cursor"):
        snapshot.page(cursor="invalid")


def test_feedback_concurrent_dedup_decisions_recovery_and_unknown_are_separate(tmp_path):
    writer, reader = located(tmp_path)
    writer.reconcile_folder_snapshot("gmail", "INBOX", "1", set())
    store = FeedbackStore(tmp_path)
    snapshot = LocationSnapshot(reader, base_url="https://mail.test")
    args = dict(
        stable_message_id=MID,
        intended_action="trash",
        user_decision="authorized",
        processing_status="blocked",
        reason_code="NO_ACTIVE_PROVIDER_LOCATION",
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda _: store.submit(snapshot, **args), range(4)))
    assert len({x["issue_id"] for x in values}) == 1
    issue_id = values[0]["issue_id"]
    value = store.get(snapshot, issue_id)
    assert len(value["history"]) == 4
    assert all(
        x["request_id"] == snapshot.request_id and x["service_version"] for x in value["history"]
    )
    assert value["feedback_url"].startswith("https://mail.test/feedback?")
    assert value["execution_result"] == "NOT_EXECUTED"
    assert value["processing_status"] == "blocked"
    assert value["feedback_grants_approval"] is False
    assert store.path.stat().st_mode & 0o077 == 0
    assert store.list(snapshot, restored_only=True)["items"] == []
    writer.upsert(message_record(MID), uid_validity="1")
    recovered = LocationSnapshot(reader)
    assert store.list(recovered, restored_only=True)["items"][0]["requires_new_approval"] is True
    unknown = LocationSnapshot(
        reader,
        executions={
            MID: [{"kind": "trash", "state": "UNKNOWN", "updated_at": value["created_at"]}]
        },
    )
    value = store.get(unknown, issue_id)
    assert value["execution_result"] == "UNKNOWN"
    assert value["processing_status"] == "unknown"
    assert value["restored_actionable"] is False
    assert unknown.counts()["location_anomaly_count"] == 1
    assert not unknown.state(MID)["actionable"]
    assert store.list(unknown, restored_only=True)["items"] == []
    with pytest.raises(ValueError, match="confirmed"):
        store.submit(snapshot, **{**args, "processing_status": "confirmed"})
    with pytest.raises(ValueError, match="current diagnostic"):
        store.submit(recovered, **args)
    assert "ordinary body" not in store.path.read_bytes().decode(errors="ignore")


def test_feedback_list_survives_a_message_removed_from_the_archive(tmp_path):
    writer, reader = located(tmp_path)
    other = "b" * 24
    writer.upsert(message_record(other, uid=2), uid_validity="1")
    writer.reconcile_folder_snapshot("gmail", "INBOX", "1", set())
    store = FeedbackStore(tmp_path)
    snapshot = LocationSnapshot(reader, base_url="https://mail.test")
    issues = {
        mid: store.submit(
            snapshot,
            stable_message_id=mid,
            intended_action="trash",
            user_decision="authorized",
            processing_status="blocked",
            reason_code="NO_ACTIVE_PROVIDER_LOCATION",
        )["issue_id"]
        for mid in (MID, other)
    }
    with open_writer(writer.hot_path) as conn:
        conn.execute("DELETE FROM messages WHERE id=?", (other,))
    current = LocationSnapshot(reader, base_url="https://mail.test")
    assert other not in current.messages
    items = {item["stable_message_id"]: item for item in store.list(current)["items"]}
    assert set(items) == {MID, other}
    assert items[MID]["processing_status"] == "blocked"
    assert items[MID]["current_location"]["reason_code"] == "NO_ACTIVE_PROVIDER_LOCATION"
    removed = items[other]
    assert removed["processing_status"] == "message_removed"
    assert removed["current_location"] is None
    assert removed["restored_actionable"] is False
    assert removed["repair_result"] == "awaiting_verification"
    assert store.get(current, issues[other])["processing_status"] == "message_removed"
    assert store.list(current, restored_only=True)["items"] == []


def test_mcp_diagnostic_feedback_scope_correlation_and_blocked_actions(tmp_path):
    writer, reader = located(tmp_path / "archive")
    writer.reconcile_folder_snapshot("gmail", "INBOX", "1", set())
    client, approvals, events = _client(reader.data_dir)
    diagnosis = _tool_value(
        _tool_call(client, "metadata", "diagnose_message", {"stable_message_id": MID})
    )
    assert diagnosis["request_id"] == events[-1]["metadata"]["request_id"]
    assert (
        _tool_call(client, "read", "diagnose_message", {"stable_message_id": MID}).status_code
        == 403
    )
    result = _tool_call(
        client, "organize", "preview_archive", {"account": "gmail", "stable_message_id": MID}
    ).json()["result"]
    assert result["isError"] is True
    detail = json.loads(result["content"][0]["text"])
    assert detail["reason_code"] == "NO_ACTIVE_PROVIDER_LOCATION"
    assert detail["feedback_url"]
    args = dict(
        stable_message_id=MID,
        intended_action="trash",
        user_decision="authorized",
        processing_status="blocked",
        reason_code=diagnosis["reason_code"],
    )
    value = _tool_value(_tool_call(client, "metadata", "submit_mail_feedback", args))
    assert value["issue_id"]
    assert not approvals.repository.approvals
    assert not approvals.repository.executions
    assert not approvals.repository.drafts
    malicious = _tool_call(
        client, "metadata", "submit_mail_feedback", {**args, "body_text": "private"}
    )
    assert malicious.json()["result"]["isError"] is True
    page = _tool_value(
        _tool_call(client, "metadata", "list_recent", {"paginated": True, "actionable_only": True})
    )
    assert page["items"] == []


def test_feedback_page_is_authenticated_and_submission_requires_csrf(tmp_path):
    credential, key, password = _admin_files(tmp_path)
    token = _private(tmp_path / "token", "mcp-token-" + "x" * 48)
    gateway = FakeGateway()
    client = TestClient(
        create_app(
            Settings(
                mail_ui_enabled=True,
                mail_ui_mcp_token_file=token,
                admin_credential_file=credential,
                admin_session_key_file=key,
                admin_secure_cookies=False,
            ),
            gateway=gateway,
        )
    )
    response = client.get("/feedback?message_id=" + MID, follow_redirects=False)
    assert response.status_code == 303
    assert "next=" in response.headers["location"]
    assert client.get("/assets/feedback.js").status_code == 401
    _login(client, password)
    session = client.get("/api/session").json()
    assert client.get("/feedback").status_code == 200
    assert client.get("/assets/feedback.js").status_code == 200
    assert client.get("/assets/feedback.css").status_code == 200
    assert client.post("/api/mcp/submit_mail_feedback", json={"arguments": {}}).status_code == 403
    response = client.post(
        "/api/mcp/diagnose_message",
        json={"arguments": {"stable_message_id": MID}},
        headers={"X-CSRF-Token": session["csrf"]},
    )
    assert response.status_code == 200
    assert gateway.calls[-1] == ("diagnose_message", {"stable_message_id": MID})


def test_sync_auth_failure_has_content_free_traceable_evidence(tmp_path):
    import imaplib

    writer = ArchiveWriter(tmp_path)
    sync = ReadOnlyMailboxSync(archive=writer, credentials=None, oauth_access_token=None)
    sync.authenticate = lambda _account: (_ for _ in ()).throw(
        imaplib.IMAP4.error("AUTHENTICATE failed private-error-text")
    )
    account = dataclasses.replace(TEST_ACCOUNTS[2], folders=("INBOX",))
    with pytest.raises(imaplib.IMAP4.error):
        sync.sync_account(account)
    with sqlite3.connect(writer.hot_path) as conn:
        attempt = conn.execute(
            "SELECT sync_run_id,status,reason_code FROM sync_attempts"
        ).fetchone()
    assert attempt[0]
    assert attempt[1:] == ("failed", "AUTHENTICATION_FAILED")
    assert b"private-error-text" not in writer.hot_path.read_bytes()


def test_verified_provider_reencoding_is_actionable_but_unknown_still_blocks(tmp_path):
    writer, reader = located(tmp_path)
    variant = dataclasses.replace(message_record(MID), raw_body_sha256="e" * 64, raw_size=200)
    writer.observe_location(variant, uid_validity="1")
    value = LocationSnapshot(reader).diagnose(MID)
    assert value["actionable"] is True
    assert value["provider_locations"][0]["identity_match_basis"] == "verified_provider_equivalence"
    assert reader.message_context(MID)["raw_body_sha256"] != variant.raw_body_sha256
    blocked = LocationSnapshot(reader, executions={MID: [{"state": "UNKNOWN"}]}).state(MID)
    assert blocked["actionable"] is False
    assert blocked["reason_code"] == "PROVIDER_OUTCOME_UNKNOWN"


@pytest.mark.parametrize(
    "field",
    ["provider_raw_body_sha256", "archive_raw_body_sha256", "uid", "uid_validity", "stable_id"],
)
def test_provider_equivalence_proof_is_bound_to_current_hashes_and_uid(tmp_path, field):
    writer, reader = located(tmp_path)
    writer.observe_location(
        dataclasses.replace(message_record(MID), raw_body_sha256="e" * 64), uid_validity="1"
    )
    with open_writer(writer.hot_path) as conn:
        conn.execute(
            f"UPDATE provider_identity_verifications SET {field}=?",  # noqa: S608 - test parameter
            ("invalid",),
        )
    state = LocationSnapshot(reader).state(MID)
    assert state["actionable"] is False
    assert state["reason_code"] == "PROVIDER_IDENTITY_MISMATCH"


def test_provider_equivalence_requires_proof_and_preserves_duplicate_uid_block(tmp_path):
    writer, reader = located(tmp_path)
    variant = dataclasses.replace(message_record(MID), raw_body_sha256="e" * 64)
    writer.observe_location(variant, uid_validity="1")
    with open_writer(writer.hot_path) as conn:
        conn.execute("DROP TABLE provider_identity_verifications")
    assert LocationSnapshot(reader).state(MID)["actionable"] is False
    writer.observe_location(variant, uid_validity="1")
    assert LocationSnapshot(reader).state(MID)["actionable"] is True
    writer.observe_location(dataclasses.replace(variant, uid=2), uid_validity="1")
    state = LocationSnapshot(reader).state(MID)
    assert state["location_status"] == "ambiguous"
    assert state["actionable"] is False


def test_verified_variant_approval_keeps_the_actual_provider_hash(tmp_path):
    writer, reader = located(tmp_path)
    variant = dataclasses.replace(message_record(MID), raw_body_sha256="e" * 64)
    writer.observe_location(variant, uid_validity="1")
    client, approvals, _events = _client(reader.data_dir)
    draft = _tool_value(
        _tool_call(
            client, "delete-draft", "preview_trash", {"account": "gmail", "stable_message_id": MID}
        )
    )
    assert draft["review_packet"]["raw_body_sha256"] == variant.raw_body_sha256
    assert reader.message_context(MID)["raw_body_sha256"] == message_record(MID).raw_body_sha256
    assert draft["requires_human_approval"] is True
    assert not approvals.repository.executions
