from __future__ import annotations

import asyncio
import concurrent.futures
import datetime as dt
import os
import shutil
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from account_fixtures import TEST_ACCOUNTS
from psycopg import sql

from evergarden.approvals.dispatcher import ApprovalDispatcher
from evergarden.approvals.models import (
    Actor,
    ApprovalSource,
    Draft,
    ExecutionState,
    IntentKind,
)
from evergarden.approvals.service import (
    UNKNOWN_RECONCILE_INTERVAL,
    ApprovalError,
    ApprovalService,
    PostgresApprovalRepository,
    ProviderNotAttempted,
    ProviderOutcomeUnknown,
)
from evergarden.auth.credential_store import generate_key
from evergarden.automations.fence import FenceConfig, LeaseToken, SideEffectFence
from evergarden.database import (
    DuplicateJobRun,
    JobLease,
    WriterControlConflict,
    advisory_key,
    append_audit_event,
    apply_migrations,
    mail_operations_status,
    reconcile_runtime_control,
    verify_audit_chain,
    writer_action_lease,
)

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
HUMAN = Actor("admin", "approval-ui", "approval-ui", True)
AGENT = Actor("agent", "codex", "mcp", False)
ALL_KINDS = frozenset(IntentKind)
FENCE = SideEffectFence(FenceConfig("host-a", "host-a", 2, True, True))
LEASE = LeaseToken("test", "slot", "host-a", 2, "nonce")
GMAIL = next(account for account in TEST_ACCOUNTS if account.alias == "gmail")
CONFIRMED_RESULT = {"status": "confirmed", "verified": True}
ONE_MICROSECOND = dt.timedelta(microseconds=1)


@pytest.fixture()
def postgres_url() -> str:
    base = os.environ.get("TEST_DATABASE_URL")
    if not base:
        pytest.skip("TEST_DATABASE_URL is not configured")
    name = "evergarden_test_" + uuid.uuid4().hex[:12]
    parts = urlsplit(base)
    admin_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/postgres", parts.query, ""))
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    test_url = urlunsplit((parts.scheme, parts.netloc, f"/{name}", parts.query, ""))
    try:
        yield test_url
    finally:
        with psycopg.connect(admin_url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


def test_postgres_other_pending_is_visible_but_never_bulk_selected(postgres_url):
    apply_migrations(postgres_url, MIGRATIONS)
    service = ApprovalService(
        PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    )
    trash = service.prepare(
        kind=IntentKind.TRASH, payload=_mail_payload(IntentKind.TRASH), actor=AGENT
    )
    archive = service.prepare(
        kind=IntentKind.ARCHIVE, payload=_mail_payload(IntentKind.ARCHIVE), actor=AGENT
    )
    page = service.pending_trash_page(limit=50, offset=0)
    assert [item["draft_id"] for item in page["drafts"]] == [trash.draft_id]
    assert [item["draft_id"] for item in page["other_drafts"]] == [archive.draft_id]
    assert page["other_total"] == 1
    assert [item["draft_id"] for item in service.pending_trash_selection()] == [trash.draft_id]
    service.approve(draft_id=archive.draft_id, payload_hash=archive.payload_hash, actor=HUMAN)
    assert service.pending_trash_page(limit=50, offset=0)["other_drafts"] == []


def _mail_payload(kind: IntentKind, stable_id: str | None = None) -> dict:
    if kind is IntentKind.SEND:
        return {
            "operation": "send",
            "account": "gmail",
            "from": GMAIL.address,
            "to": ["recipient@example.test"],
            "subject": "dispatch check",
            "body": "approved body",
            "date": "2026-10-13T12:00:00+00:00",
            "message_id": f"<{uuid.uuid4().hex}@example.test>",
        }
    payload = {
        "operation": kind.value,
        "account": "gmail",
        "stable_message_id": stable_id or uuid.uuid4().hex[:24],
        "source_folder": "INBOX",
        "source_uid": 7,
        "source_uid_validity": "777",
        "provider_message_id": "source@example.test",
        "raw_body_sha256": "b" * 64,
    }
    if kind is IntentKind.MARK:
        return {**payload, "action": "seen"}
    destination = {
        IntentKind.TRASH: GMAIL.trash_folder,
        IntentKind.ARCHIVE: GMAIL.archive_folder,
        IntentKind.MOVE: "Unrelated",
    }[kind]
    return {
        **payload,
        "destination": destination,
        "copy_preserve_source_fallback": (
            kind is not IntentKind.TRASH and GMAIL.copy_preserve_source_fallback
        ),
    }


def _prepare(
    service: ApprovalService,
    *,
    kind: IntentKind = IntentKind.TRASH,
    lifetime: dt.timedelta = dt.timedelta(hours=1),
    approval_lifetime: dt.timedelta = dt.timedelta(minutes=60),
    stable_id: str | None = None,
) -> Draft:
    return service.prepare(
        kind=kind,
        payload=_mail_payload(kind, stable_id),
        actor=AGENT,
        lifetime=lifetime,
        approval_lifetime=approval_lifetime,
    )


def _approve(service: ApprovalService, draft: Draft, **kwargs):
    return service.approve(
        draft_id=draft.draft_id, payload_hash=draft.payload_hash, actor=HUMAN, **kwargs
    )


def _executor(service: ApprovalService, provider):
    return lambda **kwargs: service.execute(**kwargs, fence=FENCE, lease=LEASE, executor=provider)


def _claim(repository: PostgresApprovalRepository, approval, draft: Draft, now: dt.datetime):
    execution, claimed = repository.claim_execution(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        kind=draft.kind,
        payload_hash=draft.payload_hash,
        now=now,
    )
    assert claimed is True
    return execution


def _settle(
    repository: PostgresApprovalRepository,
    approval,
    now: dt.datetime,
    state: ExecutionState,
    *,
    error_class: str | None = None,
):
    return repository.transition_execution(
        approval.approval_id,
        expected=frozenset({ExecutionState.ATTEMPTING}),
        state=state,
        now=now,
        error_class=error_class,
    )


def test_postgres_migrations_and_append_only_guards(postgres_url: str) -> None:
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    assert apply_migrations(postgres_url, migrations) == [
        "001_initial.sql",
        "002_mail_action_lifecycle.sql",
        "003_reversible_trash.sql",
        "004_human_dispatch_and_retry.sql",
        "005_execution_attempted_at.sql",
        "006_durable_human_approvals.sql",
        "007_free_writer_identity.sql",
    ]
    assert apply_migrations(postgres_url, migrations) == []
    with psycopg.connect(postgres_url) as conn:
        # A fresh database has no writer until a host claims it.
        assert conn.execute(
            "SELECT active_writer,writer_epoch,side_effects_enabled FROM runtime_control"
        ).fetchone() == ("none", 1, False)

    with psycopg.connect(postgres_url) as conn:
        with pytest.raises(psycopg.Error, match="DELETE is forbidden"):
            conn.execute("DELETE FROM notification_outbox")
        conn.rollback()
        with pytest.raises(psycopg.Error, match="DELETE is forbidden"):
            conn.execute("DELETE FROM mail_action_ledger")

    append_audit_event(
        postgres_url,
        event_type="mcp.tool",
        actor="user",
        client_id="codex",
        outcome="SUCCESS",
        metadata={"tool": "get_message", "access_token": "must-not-persist"},
    )
    append_audit_event(
        postgres_url,
        event_type="mcp.tool",
        actor="user",
        client_id="codex",
        outcome="DENIED",
        metadata={"tool": "send_approved"},
    )
    chain = verify_audit_chain(postgres_url)
    assert chain["valid"] is True
    assert chain["events"] == 2
    status = mail_operations_status(postgres_url)
    assert status["active_writer"] == "none"
    assert status["side_effects_enabled"] is False
    assert status["mail_action_states"] == {}
    with psycopg.connect(postgres_url) as conn:
        assert (
            conn.execute("SELECT metadata->>'access_token' FROM audit_events LIMIT 1").fetchone()[0]
            == "[REDACTED]"
        )
        with pytest.raises(psycopg.Error, match="immutable"):
            conn.execute("UPDATE audit_events SET outcome='FAILED'")


def test_postgres_job_lease_is_unique_by_slot_and_epoch(postgres_url: str) -> None:
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    apply_migrations(postgres_url, migrations)
    assert isinstance(advisory_key("job", "slot"), int)
    first = JobLease(
        database_url=postgres_url,
        job_id="archive-sync",
        scheduled_slot="slot-1",
        host="host-a",
        owner_epoch=1,
    )
    with first:
        with pytest.raises(DuplicateJobRun, match="already held"):
            with JobLease(
                database_url=postgres_url,
                job_id="archive-sync",
                scheduled_slot="slot-1",
                host="host-a",
                owner_epoch=1,
            ):
                pass
        first.finish("SUCCESS")
    with pytest.raises(DuplicateJobRun, match="authoritative"):
        with JobLease(
            database_url=postgres_url,
            job_id="archive-sync",
            scheduled_slot="slot-1",
            host="host-a",
            owner_epoch=1,
        ):
            pass
    with pytest.raises(DuplicateJobRun, match="epoch"):
        with JobLease(
            database_url=postgres_url,
            job_id="archive-sync",
            scheduled_slot="slot-2",
            host="host-a",
            owner_epoch=2,
        ):
            pass


def test_postgres_writer_action_lease_requires_database_control_and_is_exclusive(
    postgres_url: str,
) -> None:
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    apply_migrations(postgres_url, migrations)
    with pytest.raises(RuntimeError, match="does not authorize"):
        with writer_action_lease(
            postgres_url, action_slot="approval-1", host="host-a", owner_epoch=1
        ):
            pass
    with psycopg.connect(postgres_url) as conn:
        conn.execute(
            "UPDATE runtime_control SET active_writer='host-a',writer_epoch=2,"
            "side_effects_enabled=TRUE"
        )
    with writer_action_lease(
        postgres_url, action_slot="approval-1", host="host-a", owner_epoch=2
    ) as lease:
        assert lease.owner_host == "host-a"
        assert lease.writer_epoch == 2
        with pytest.raises(RuntimeError, match="already held"):
            with writer_action_lease(
                postgres_url,
                action_slot="approval-1",
                host="host-a",
                owner_epoch=2,
            ):
                pass


def _runtime_control(url: str) -> tuple:
    with psycopg.connect(url) as conn:
        return conn.execute(
            "SELECT active_writer,writer_epoch,side_effects_enabled,updated_at FROM runtime_control"
        ).fetchone()


def test_postgres_fresh_install_claims_writer_control_for_any_host_name(
    postgres_url: str,
) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    # Read-only first start: the row records this host, writes stay off.
    assert reconcile_runtime_control(
        postgres_url,
        host="mail-box.lan",
        active_writer="mail-box.lan",
        writer_epoch=1,
        side_effects_enabled=False,
    )["changed"]
    assert _runtime_control(postgres_url)[:3] == ("mail-box.lan", 1, False)
    with pytest.raises(RuntimeError, match="does not authorize"):
        with writer_action_lease(
            postgres_url, action_slot="approval-1", host="mail-box.lan", owner_epoch=1
        ):
            pass
    # The single switch: enable side effects and migrate again.
    reconcile_runtime_control(
        postgres_url,
        host="mail-box.lan",
        active_writer="mail-box.lan",
        writer_epoch=1,
        side_effects_enabled=True,
    )
    with writer_action_lease(
        postgres_url, action_slot="approval-1", host="mail-box.lan", owner_epoch=1
    ) as lease:
        assert lease.owner_host == "mail-box.lan"
    with pytest.raises(WriterControlConflict, match="another writer"):
        reconcile_runtime_control(
            postgres_url,
            host="host-b",
            active_writer="host-b",
            writer_epoch=2,
            side_effects_enabled=True,
        )
    assert _runtime_control(postgres_url)[:3] == ("mail-box.lan", 1, True)
    with psycopg.connect(postgres_url) as conn:
        for invalid in ("", "has space", "x" * 64):
            with pytest.raises(psycopg.errors.CheckViolation):
                conn.execute("UPDATE runtime_control SET active_writer=%s", (invalid,))
            conn.rollback()


LEGACY_PARITY_REPORTS_DDL = """
CREATE TABLE parity_reports (
    report_id UUID PRIMARY KEY,
    scheduled_slot TEXT NOT NULL UNIQUE,
    source_count BIGINT NOT NULL,
    target_count BIGINT NOT NULL,
    missing_ids JSONB NOT NULL,
    extra_ids JSONB NOT NULL,
    explained_differences JSONB NOT NULL,
    major_difference BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER parity_reports_no_delete BEFORE DELETE ON parity_reports
FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();
"""


def test_postgres_upgrade_from_closed_writer_list_keeps_the_live_writer_row(
    postgres_url: str, tmp_path: Path
) -> None:
    """An existing deployment applied 001..006 when the writer was a closed list."""
    legacy = tmp_path / "legacy-migrations"
    legacy.mkdir()
    current_initial = (MIGRATIONS / "001_initial.sql").read_text(encoding="utf-8")
    legacy_initial = current_initial.replace(
        "CHECK (active_writer ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')",
        "CHECK (active_writer IN ('host-a','host-b','none'))",
    ).replace("VALUES (TRUE,'none',1,FALSE);", "VALUES (TRUE,'host-b',1,FALSE);")
    ledger_trigger = (
        "CREATE TRIGGER notification_ledger_no_delete BEFORE DELETE ON "
        "notification_delivery_ledger\n"
        "FOR EACH STATEMENT EXECUTE FUNCTION evergarden_forbid_delete();\n"
    )
    assert ledger_trigger in legacy_initial
    # The original 001 also carried a parity report table guarded by the
    # delete trigger; fresh installs no longer create it, upgrades keep it.
    legacy_initial = legacy_initial.replace(
        ledger_trigger,
        ledger_trigger + LEGACY_PARITY_REPORTS_DDL,
    )
    assert legacy_initial != current_initial
    (legacy / "001_initial.sql").write_text(legacy_initial, encoding="utf-8")
    for path in MIGRATIONS.glob("*.sql"):
        if "001_initial.sql" < path.name < "007_free_writer_identity.sql":
            (legacy / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    assert len(apply_migrations(postgres_url, legacy)) == 6
    with psycopg.connect(postgres_url) as conn:
        conn.execute(
            "UPDATE runtime_control SET active_writer='host-a',writer_epoch=2,"
            "side_effects_enabled=TRUE"
        )
        conn.execute(
            "INSERT INTO parity_reports(report_id,scheduled_slot,source_count,target_count,"
            "missing_ids,extra_ids,explained_differences,major_difference) "
            "VALUES (gen_random_uuid(),'slot-1',1,1,'[]','[]','[]',FALSE)"
        )
    with psycopg.connect(postgres_url) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("UPDATE runtime_control SET active_writer='mail-box.lan'")
        conn.rollback()
    before = _runtime_control(postgres_url)

    assert apply_migrations(postgres_url, MIGRATIONS) == ["007_free_writer_identity.sql"]
    assert _runtime_control(postgres_url) == before
    assert reconcile_runtime_control(
        postgres_url,
        host="host-a",
        active_writer="host-a",
        writer_epoch=2,
        side_effects_enabled=True,
    ) == {
        "active_writer": "host-a",
        "writer_epoch": 2,
        "side_effects_enabled": True,
        "changed": False,
    }
    assert _runtime_control(postgres_url) == before
    with writer_action_lease(
        postgres_url, action_slot="approval-1", host="host-a", owner_epoch=2
    ) as lease:
        assert (lease.owner_host, lease.writer_epoch) == ("host-a", 2)
    with psycopg.connect(postgres_url) as conn:
        conn.execute("UPDATE runtime_control SET active_writer='mail-box.lan'")
        conn.rollback()
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("UPDATE runtime_control SET active_writer='bad writer'")
        conn.rollback()
        assert conn.execute("SELECT count(*) FROM parity_reports").fetchone() == (1,)
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("DELETE FROM parity_reports")


def test_postgres_audit_chain_remains_valid_under_concurrency(postgres_url: str) -> None:
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    apply_migrations(postgres_url, migrations)

    def append(index: int) -> str:
        return append_audit_event(
            postgres_url,
            event_type="mcp.tool",
            actor=f"actor-{index}",
            client_id="concurrency-test",
            outcome="SUCCESS",
            metadata={"tool": "health_status"},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        event_ids = list(pool.map(append, range(24)))
    assert len(set(event_ids)) == 24
    assert verify_audit_chain(postgres_url)["valid"] is True
    assert verify_audit_chain(postgres_url)["events"] == 24


def test_postgres_approval_repository_is_encrypted_cross_process_and_recoverable(
    postgres_url: str,
) -> None:
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    apply_migrations(postgres_url, migrations)
    key = generate_key()
    first = ApprovalService(PostgresApprovalRepository(postgres_url, key=key, host_id="host-a"))
    payload = {
        "operation": "send",
        "account": "gmail",
        "from": "sender@example.test",
        "to": ["recipient@example.test"],
        "subject": "confidential review",
        "body": "draft payload",
        "date": "2026-08-17T12:00:00+00:00",
        "message_id": "<draft@example.test>",
    }
    draft = first.prepare(
        kind=IntentKind.SEND,
        payload=payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    with psycopg.connect(postgres_url) as conn:
        encrypted = bytes(
            conn.execute(
                "SELECT encrypted_payload FROM approval_drafts WHERE draft_id=%s",
                (draft.draft_id,),
            ).fetchone()[0]
        )
    assert b"confidential review" not in encrypted
    assert b"draft payload" not in encrypted

    second = ApprovalService(PostgresApprovalRepository(postgres_url, key=key, host_id="host-a"))
    loaded = second.repository.get_draft(draft.draft_id)
    assert loaded.payload == payload
    approval = second.approve(
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )
    with pytest.raises(ApprovalError, match="already has"):
        second.approve(
            draft_id=draft.draft_id,
            payload_hash=draft.payload_hash,
            actor=Actor("eric", "approval-ui", "approval-ui", True),
        )
    third = PostgresApprovalRepository(postgres_url, key=key, host_id="host-a")
    execution, claimed = third.claim_execution(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        kind=IntentKind.SEND,
        payload_hash=draft.payload_hash,
        now=approval.approved_at,
    )
    assert claimed is True
    replay, claimed = PostgresApprovalRepository(
        postgres_url, key=key, host_id="host-a"
    ).claim_execution(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        kind=IntentKind.SEND,
        payload_hash=draft.payload_hash,
        now=approval.approved_at,
    )
    assert claimed is False
    assert replay.action_id == execution.action_id
    confirmed = third.transition_execution(
        approval.approval_id,
        expected=frozenset({ExecutionState.ATTEMPTING}),
        state=ExecutionState.CONFIRMED,
        now=approval.approved_at,
        provider_object_id="<approved@example.test>",
        provider_result={
            "status": "confirmed",
            "operation": "send",
            "message_id": "<approved@example.test>",
        },
    )
    assert confirmed.state is ExecutionState.CONFIRMED
    assert mail_operations_status(postgres_url)["mail_action_states"] == {"CONFIRMED": 1}
    with psycopg.connect(postgres_url) as conn:
        assert (
            conn.execute(
                "SELECT provider_object_id FROM approvals WHERE approval_id=%s",
                (approval.approval_id,),
            ).fetchone()[0]
            == "<approved@example.test>"
        )
        with pytest.raises(psycopg.Error, match="DELETE is forbidden"):
            conn.execute("DELETE FROM mail_action_ledger")

    concurrent_payload = {**payload, "message_id": "<concurrent@example.test>"}
    concurrent_draft = second.prepare(
        kind=IntentKind.SEND,
        payload=concurrent_payload,
        actor=Actor("agent", "codex", "mcp", False),
    )
    concurrent_approval = second.approve(
        draft_id=concurrent_draft.draft_id,
        payload_hash=concurrent_draft.payload_hash,
        actor=Actor("eric", "approval-ui", "approval-ui", True),
    )

    def claim_concurrently(_index: int):
        repository = PostgresApprovalRepository(postgres_url, key=key, host_id="host-a")
        return repository.claim_execution(
            approval_id=concurrent_approval.approval_id,
            draft_id=concurrent_draft.draft_id,
            kind=IntentKind.SEND,
            payload_hash=concurrent_draft.payload_hash,
            now=concurrent_approval.approved_at,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        concurrent_claims = list(pool.map(claim_concurrently, range(8)))
    assert sum(claimed for _execution, claimed in concurrent_claims) == 1
    assert len({execution.action_id for execution, _claimed in concurrent_claims}) == 1
    with pytest.raises(ApprovalError, match="authentication"):
        PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a").get_draft(
            draft.draft_id
        )


def test_postgres_pending_trash_filters_and_pages(postgres_url: str) -> None:
    import datetime as dt

    from evergarden.approvals.models import Draft

    apply_migrations(postgres_url, Path(__file__).resolve().parents[1] / "migrations")
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    now = dt.datetime.now(dt.UTC)
    drafts = []
    for index, kind in enumerate([IntentKind.TRASH] * 4 + [IntentKind.MARK]):
        draft = Draft(
            draft_id=str(uuid.uuid4()),
            kind=kind,
            payload={"test": index},
            payload_hash=str(index) * 64,
            created_by="agent",
            created_client="codex",
            created_at=now + dt.timedelta(microseconds=index),
            expires_at=now + dt.timedelta(minutes=-1 if index == 3 else 30),
        )
        repo.add_draft(draft)
        drafts.append(draft)
    service = ApprovalService(repo)
    service.approve(
        draft_id=drafts[2].draft_id,
        payload_hash=drafts[2].payload_hash,
        actor=Actor("admin", "approval-ui", "approval-ui", True),
    )

    def page_ids(offset: int) -> list[str]:
        page = service.pending_trash_page(limit=1, offset=offset)
        return [item["draft_id"] for item in page["drafts"]]

    assert page_ids(0) == [drafts[0].draft_id]
    assert page_ids(1) == [drafts[1].draft_id]
    assert page_ids(2) == []
    assert service.review(drafts[0].draft_id)["review_packet"] == {"test": 0}


def test_postgres_migration_004_classifies_existing_approvals_and_allows_retryable(
    postgres_url: str, tmp_path: Path
) -> None:
    before_004 = tmp_path / "before-004"
    before_004.mkdir()
    for path in MIGRATIONS.glob("*.sql"):
        if path.name < "004_human_dispatch_and_retry.sql":
            shutil.copy(path, before_004 / path.name)
    assert apply_migrations(postgres_url, before_004) == [
        "001_initial.sql",
        "002_mail_action_lifecycle.sql",
        "003_reversible_trash.sql",
    ]
    now = dt.datetime.now(dt.UTC)
    expected_sources = {
        ("approval-ui", "trash"): "human",
        ("approval-ui", "archive"): "human",
        ("admin-cli", "mark"): "human",
        ("codex-admin-cli", "trash"): "human",
        ("codex-admin-cli", "archive"): "policy",
        ("codex", "archive"): "policy",
        ("chatgpt-evergarden", "send"): "policy",
        ("deployment-smoke", "move"): "policy",
    }

    def seed(conn, client: str, kind: str) -> tuple[uuid.UUID, uuid.UUID]:
        draft_id, approval_id = uuid.uuid4(), uuid.uuid4()
        conn.execute(
            """
            INSERT INTO approval_drafts(
              draft_id,kind,payload_hash,encrypted_payload,created_by,client_id,expires_at
            ) VALUES (%s,%s,%s,%s,'agent','codex',%s)
            """,
            (draft_id, kind, "a" * 64, b"sealed", now + dt.timedelta(hours=1)),
        )
        conn.execute(
            """
            INSERT INTO approvals(
              approval_id,draft_id,payload_hash,approved_by,approved_client,approved_at,expires_at
            ) VALUES (%s,%s,%s,'admin',%s,%s,%s)
            """,
            (approval_id, draft_id, "a" * 64, client, now, now + dt.timedelta(hours=1)),
        )
        return draft_id, approval_id

    def retryable_row(draft_id: uuid.UUID, approval_id: uuid.UUID) -> tuple:
        return (uuid.uuid4(), approval_id, draft_id, "trash", "a" * 64, uuid.uuid4().hex)

    insert_ledger = """
        INSERT INTO mail_action_ledger(
          action_id,approval_id,draft_id,kind,payload_hash,idempotency_key,state
        ) VALUES (%s,%s,%s,%s,%s,%s,'RETRYABLE')
        """
    with psycopg.connect(postgres_url) as conn:
        seeded = [seed(conn, client, kind) for client, kind in expected_sources]
    trash_draft_id, trash_approval_id = seeded[0]
    with psycopg.connect(postgres_url) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(insert_ledger, retryable_row(trash_draft_id, trash_approval_id))

    assert apply_migrations(postgres_url, MIGRATIONS) == [
        "004_human_dispatch_and_retry.sql",
        "005_execution_attempted_at.sql",
        "006_durable_human_approvals.sql",
        "007_free_writer_identity.sql",
    ]
    with psycopg.connect(postgres_url) as conn:
        rows = conn.execute(
            "SELECT a.approved_client,d.kind,a.approval_source "
            "FROM approvals a JOIN approval_drafts d USING(draft_id)"
        ).fetchall()
        assert {(client, kind): source for client, kind, source in rows} == expected_sources
        # Writers from before the cut-over omit the column and get the compatible default.
        _, legacy_approval_id = seed(conn, "approval-ui", "trash")
        assert (
            conn.execute(
                "SELECT approval_source FROM approvals WHERE approval_id=%s",
                (legacy_approval_id,),
            ).fetchone()[0]
            == "policy"
        )
        conn.execute(insert_ledger, retryable_row(trash_draft_id, trash_approval_id))
        assert conn.execute(
            "SELECT state FROM mail_action_ledger WHERE approval_id=%s", (trash_approval_id,)
        ).fetchone() == ("RETRYABLE",)
    with psycopg.connect(postgres_url) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "UPDATE approvals SET approval_source='robot' WHERE approval_id=%s",
            (legacy_approval_id,),
        )
    with psycopg.connect(postgres_url) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "UPDATE mail_action_ledger SET state='PAUSED' WHERE approval_id=%s",
            (trash_approval_id,),
        )


def test_postgres_migration_005_backfills_the_current_attempt_start(
    postgres_url: str, tmp_path: Path
) -> None:
    before_005 = tmp_path / "before-005"
    before_005.mkdir()
    for path in MIGRATIONS.glob("*.sql"):
        if path.name < "005_execution_attempted_at.sql":
            shutil.copy(path, before_005 / path.name)
    apply_migrations(postgres_url, before_005)
    created = dt.datetime(2026, 10, 10, tzinfo=dt.UTC)
    retried = created + dt.timedelta(hours=30)
    rows = {}
    with psycopg.connect(postgres_url) as conn:
        for attempt in (1, 2):
            draft_id, approval_id = uuid.uuid4(), uuid.uuid4()
            conn.execute(
                "INSERT INTO approval_drafts(draft_id,kind,payload_hash,encrypted_payload,"
                "created_by,client_id,expires_at) VALUES (%s,'trash',%s,%s,'agent','codex',%s)",
                (draft_id, "a" * 64, b"sealed", retried),
            )
            conn.execute(
                "INSERT INTO approvals(approval_id,draft_id,payload_hash,approved_by,"
                "approved_client,approved_at,expires_at) VALUES (%s,%s,%s,'admin','approval-ui',%s,%s)",
                (approval_id, draft_id, "a" * 64, created, retried),
            )
            conn.execute(
                "INSERT INTO mail_action_ledger(action_id,approval_id,draft_id,kind,payload_hash,"
                "idempotency_key,state,attempt,created_at,updated_at) "
                "VALUES (%s,%s,%s,'trash',%s,%s,'UNKNOWN',%s,%s,%s)",
                (
                    uuid.uuid4(),
                    approval_id,
                    draft_id,
                    "a" * 64,
                    uuid.uuid4().hex,
                    attempt,
                    created,
                    retried,
                ),
            )
            rows[attempt] = approval_id

    assert apply_migrations(postgres_url, MIGRATIONS) == [
        "005_execution_attempted_at.sql",
        "006_durable_human_approvals.sql",
        "007_free_writer_identity.sql",
    ]
    with psycopg.connect(postgres_url) as conn:
        attempted = dict(
            conn.execute("SELECT approval_id,attempted_at FROM mail_action_ledger").fetchall()
        )
    # A first attempt starts at creation; a retried one at its latest possible start.
    assert attempted[rows[1]] == created
    assert attempted[rows[2]] == retried


def test_postgres_migration_006_makes_open_human_approvals_durable(
    postgres_url: str, tmp_path: Path
) -> None:
    before_006 = tmp_path / "before-006"
    before_006.mkdir()
    for path in MIGRATIONS.glob("*.sql"):
        if path.name < "006_durable_human_approvals.sql":
            shutil.copy(path, before_006 / path.name)
    apply_migrations(postgres_url, before_006)
    now = dt.datetime.now(dt.UTC)
    rows = {}
    with psycopg.connect(postgres_url) as conn:

        def seed(
            name: str,
            *,
            expires_in: dt.timedelta,
            source: str = "human",
            consumed: bool = False,
            state: str | None = None,
        ) -> None:
            draft_id, approval_id = uuid.uuid4(), uuid.uuid4()
            conn.execute(
                "INSERT INTO approval_drafts(draft_id,kind,payload_hash,encrypted_payload,"
                "created_by,client_id,expires_at) VALUES (%s,'trash',%s,%s,'agent','codex',%s)",
                (draft_id, "a" * 64, b"sealed", now + dt.timedelta(hours=1)),
            )
            conn.execute(
                "INSERT INTO approvals(approval_id,draft_id,payload_hash,approved_by,"
                "approved_client,approved_at,expires_at,approval_source,consumed_at) "
                "VALUES (%s,%s,%s,'admin','approval-ui',%s,%s,%s,%s)",
                (
                    approval_id,
                    draft_id,
                    "a" * 64,
                    now - dt.timedelta(hours=25),
                    now + expires_in,
                    source,
                    now - dt.timedelta(hours=24) if consumed else None,
                ),
            )
            if state is not None:
                conn.execute(
                    "INSERT INTO mail_action_ledger(action_id,approval_id,draft_id,kind,"
                    "payload_hash,idempotency_key,state) VALUES (%s,%s,%s,'trash',%s,%s,%s)",
                    (uuid.uuid4(), approval_id, draft_id, "a" * 64, uuid.uuid4().hex, state),
                )
            rows[name] = approval_id

        seed("waiting", expires_in=dt.timedelta(hours=1))
        seed("lapsed", expires_in=dt.timedelta(hours=-1))
        seed("retryable", expires_in=dt.timedelta(hours=1), consumed=True, state="RETRYABLE")
        seed(
            "lapsed_retryable",
            expires_in=dt.timedelta(hours=-1),
            consumed=True,
            state="RETRYABLE",
        )
        seed("confirmed", expires_in=dt.timedelta(hours=-1), consumed=True, state="CONFIRMED")
        seed("policy", expires_in=dt.timedelta(hours=-1), source="policy")

    assert apply_migrations(postgres_url, MIGRATIONS) == [
        "006_durable_human_approvals.sql",
        "007_free_writer_identity.sql",
    ]
    with psycopg.connect(postgres_url) as conn:
        stored = {
            name: conn.execute(
                "SELECT a.expires_at IS NULL,a.revoked_at IS NOT NULL,l.state,l.error_class "
                "FROM approvals a LEFT JOIN mail_action_ledger l USING(approval_id) "
                "WHERE a.approval_id=%s",
                (approval_id,),
            ).fetchone()
            for name, approval_id in rows.items()
        }
    # Open human work becomes durable; lapsed open work is closed, not resurrected.
    assert stored["waiting"] == (True, False, None, None)
    assert stored["lapsed"] == (False, True, None, None)
    assert stored["retryable"] == (True, False, "RETRYABLE", None)
    assert stored["lapsed_retryable"] == (False, False, "FAILED", "ApprovalLapsedBeforeRetry")
    # Finished and policy rows keep their historical expiry untouched.
    assert stored["confirmed"] == (False, False, "CONFIRMED", None)
    assert stored["policy"] == (False, False, None, None)


def test_postgres_ready_human_approvals_select_open_human_work_and_back_off_retries(
    postgres_url: str,
) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    clock = [dt.datetime.now(dt.UTC)]
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])
    policy = ApprovalService(
        repo, now=lambda: clock[0], auto_approve_kinds=frozenset({IntentKind.ARCHIVE})
    )

    def approved(kind: IntentKind = IntentKind.TRASH, **kwargs):
        clock[0] += dt.timedelta(milliseconds=1)
        draft = _prepare(service, kind=kind)
        return draft, _approve(service, draft, **kwargs)

    trash_draft, trash = approved()
    archive_draft, archive = approved(IntentKind.ARCHIVE)
    retry_draft, retry = approved()
    revoked_draft, _revoked = approved()
    repo.revoke_approvals([(revoked_draft.draft_id, revoked_draft.payload_hash)], now=clock[0])
    claimed_draft, claimed = approved()
    _claim(repo, claimed, claimed_draft, clock[0])
    consumed_draft, consumed = approved()
    repo.consume(
        consumed.approval_id, consumed_draft.draft_id, consumed_draft.payload_hash, clock[0]
    )
    _prepare(policy, kind=IntentKind.ARCHIVE)
    _prepare(service)
    _claim(repo, retry, retry_draft, clock[0])
    _settle(repo, retry, clock[0], ExecutionState.RETRYABLE, error_class="ProviderNotAttempted")
    retried_at = clock[0]

    def ready(at: dt.datetime, kinds=ALL_KINDS, *, limit: int = 10, offset: int = 0):
        return repo.ready_human_approvals(at, kinds=kinds, limit=limit, offset=offset)

    open_pairs = [
        (trash.approval_id, trash_draft.draft_id),
        (archive.approval_id, archive_draft.draft_id),
    ]
    retry_pair = (retry.approval_id, retry_draft.draft_id)
    assert ready(retried_at) == open_pairs
    assert ready(retried_at, frozenset({IntentKind.TRASH})) == open_pairs[:1]
    assert ready(retried_at, frozenset({IntentKind.SEND})) == []
    assert ready(retried_at, limit=1, offset=1) == open_pairs[1:]
    # A retry waiting for its backoff still occupies dispatcher capacity.
    assert ApprovalService(repo, now=lambda: retried_at).ready_human_count() == 3

    at = retried_at
    for attempt in range(1, 7):
        backoff = dt.timedelta(seconds=min(60 * attempt, 300))
        assert retry_pair not in ready(at + backoff - ONE_MICROSECOND)
        assert ready(at + backoff) == [*open_pairs, retry_pair]
        at += backoff
        execution, reclaimed = repo.claim_execution(
            approval_id=retry.approval_id,
            draft_id=retry_draft.draft_id,
            kind=retry_draft.kind,
            payload_hash=retry_draft.payload_hash,
            now=at,
        )
        assert reclaimed is True and execution.attempt == attempt + 1
        _settle(repo, retry, at, ExecutionState.RETRYABLE, error_class="ProviderNotAttempted")

    # Revoking the durable retryable approval is the only way to retire it.
    repo.revoke_approvals([(retry_draft.draft_id, retry_draft.payload_hash)], now=at)
    assert ready(at + dt.timedelta(days=30)) == open_pairs
    assert ApprovalService(repo, now=lambda: at).ready_human_count() == 2


def test_postgres_retryable_reclaim_increments_attempt_once_until_revoked(
    postgres_url: str,
) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    key = generate_key()
    now = dt.datetime.now(dt.UTC)
    repo = PostgresApprovalRepository(postgres_url, key=key, host_id="host-a")
    service = ApprovalService(repo, now=lambda: now)
    draft = _prepare(service)
    approval = _approve(service, draft)
    first = _claim(repo, approval, draft, now)
    assert (first.attempt, first.attempted_at) == (1, now)
    _settle(repo, approval, now, ExecutionState.RETRYABLE, error_class="ProviderNotAttempted")

    def claim(at: dt.datetime):
        return PostgresApprovalRepository(postgres_url, key=key, host_id="host-a").claim_execution(
            approval_id=approval.approval_id,
            draft_id=draft.draft_id,
            kind=draft.kind,
            payload_hash=draft.payload_hash,
            now=at,
        )

    retry_at = now + dt.timedelta(minutes=1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(claim, [retry_at] * 8))
    winners = [execution for execution, claimed in claims if claimed]
    assert len(winners) == 1
    retried = winners[0]
    assert (retried.state, retried.attempt, retried.error_class, retried.updated_at) == (
        ExecutionState.ATTEMPTING,
        2,
        None,
        retry_at,
    )
    assert (retried.action_id, retried.idempotency_key) == (first.action_id, first.idempotency_key)
    # A retry starts a new attempt; the give-up window counts from it.
    assert (retried.created_at, retried.attempted_at) == (now, retry_at)
    assert {
        (execution.state, execution.attempt) for execution, claimed in claims if not claimed
    } == {(ExecutionState.ATTEMPTING, 2)}

    _settle(repo, approval, retry_at, ExecutionState.RETRYABLE, error_class="ProviderNotAttempted")
    # The durable approval still reclaims days later; revoking it stops the retries.
    later = retry_at + dt.timedelta(days=30)
    last, claimed = claim(later)
    assert claimed is True and last.attempt == 3
    _settle(repo, approval, later, ExecutionState.RETRYABLE, error_class="ProviderNotAttempted")
    repo.revoke_approvals([(draft.draft_id, draft.payload_hash)], now=later)
    blocked, claimed = claim(later + dt.timedelta(minutes=10))
    assert claimed is False
    assert (blocked.state, blocked.attempt) == (ExecutionState.RETRYABLE, 3)
    stored = repo.get_execution_for_approval(approval.approval_id)
    assert (stored.state, stored.attempt) == (ExecutionState.RETRYABLE, 3)


def test_postgres_revoke_and_retry_claim_never_both_win(postgres_url: str) -> None:
    """A revoke racing the retry claim ends exactly one way: revoked and never
    reattempted, or reattempted and not revoked."""
    apply_migrations(postgres_url, MIGRATIONS)
    key = generate_key()
    repo = PostgresApprovalRepository(postgres_url, key=key, host_id="host-a")
    service = ApprovalService(repo, now=lambda: dt.datetime.now(dt.UTC))
    for _ in range(10):
        draft = _prepare(service)
        approval = _approve(service, draft)
        t0 = dt.datetime.now(dt.UTC)
        _claim(repo, approval, draft, t0)
        _settle(repo, approval, t0, ExecutionState.RETRYABLE, error_class="ProviderNotAttempted")
        barrier = threading.Barrier(2)
        later = t0 + dt.timedelta(minutes=5)

        def claim(barrier=barrier, approval=approval, draft=draft, later=later):
            barrier.wait()
            return PostgresApprovalRepository(
                postgres_url, key=key, host_id="host-a"
            ).claim_execution(
                approval_id=approval.approval_id,
                draft_id=draft.draft_id,
                kind=draft.kind,
                payload_hash=draft.payload_hash,
                now=later,
            )

        def revoke(barrier=barrier, draft=draft, later=later):
            barrier.wait()
            return PostgresApprovalRepository(
                postgres_url, key=key, host_id="host-a"
            ).revoke_approvals([(draft.draft_id, draft.payload_hash)], now=later)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            claimed_future = pool.submit(claim)
            revoked_rows = pool.submit(revoke).result()
            _execution, claimed = claimed_future.result()
        stored = repo.get_execution_for_approval(approval.approval_id)
        if revoked_rows:
            # The revoke won: the ledger row must never have been reopened.
            assert claimed is False
            assert stored.state is ExecutionState.RETRYABLE
            assert repo.get_approval_for_draft(draft.draft_id).revoked_at is not None
        else:
            # The claim won: the approval must not read as revoked.
            assert claimed is True
            assert stored.state is ExecutionState.ATTEMPTING
            assert repo.get_approval_for_draft(draft.draft_id).revoked_at is None


def test_postgres_revoke_approvals_closes_only_open_human_work(postgres_url: str) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    t0 = dt.datetime.now(dt.UTC)
    clock = [t0]
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])
    policy = ApprovalService(
        repo, now=lambda: clock[0], auto_approve_kinds=frozenset({IntentKind.ARCHIVE})
    )

    def approved(state: ExecutionState | None = None, error_class: str | None = None):
        draft = _prepare(service)
        approval = _approve(service, draft)
        if state is not None:
            _claim(repo, approval, draft, t0)
            _settle(repo, approval, t0, state, error_class=error_class)
        return draft, approval

    never_draft, never = approved()
    retry_draft, retry = approved(ExecutionState.RETRYABLE, "ProviderNotAttempted")
    wrong_hash_draft, wrong_hash = approved()
    unknown_draft, _unknown = approved(ExecutionState.UNKNOWN, "TimeoutError")
    confirmed_draft, _confirmed = approved(ExecutionState.CONFIRMED)
    failed_draft, _failed = approved(ExecutionState.FAILED, "ProviderDefinitelyRejected")
    policy_draft = _prepare(policy, kind=IntentKind.ARCHIVE)
    # A durable approval is open to revoke no matter how much later it happens.
    now = t0 + dt.timedelta(days=30)
    clock[0] = now

    requested = [
        (draft.draft_id, draft.payload_hash)
        for draft in (
            never_draft,
            retry_draft,
            unknown_draft,
            confirmed_draft,
            failed_draft,
            policy_draft,
        )
    ] + [(wrong_hash_draft.draft_id, "0" * 64)]
    rows = repo.revoke_approvals(requested, now=now)
    assert {row["approval_id"]: row for row in rows} == {
        approval.approval_id: {
            "approval_id": approval.approval_id,
            "draft_id": draft.draft_id,
            "previous_state": state,
        }
        for draft, approval, state in (
            (never_draft, never, None),
            (retry_draft, retry, "RETRYABLE"),
        )
    }
    for draft, when in ((never_draft, now), (retry_draft, now)):
        stored = repo.get_approval_for_draft(draft.draft_id)
        assert (stored.revoked_at, stored.consumed_at is not None) == (when, draft is retry_draft)
    # Claimed, finished, policy and hash-mismatched rows stay untouched.
    for draft in (unknown_draft, confirmed_draft, failed_draft, policy_draft, wrong_hash_draft):
        assert repo.get_approval_for_draft(draft.draft_id).revoked_at is None
    assert repo.revoke_approvals(requested, now=now) == []
    assert repo.revoke_approvals([], now=now) == []
    # Only the hash-mismatched (hence untouched) approval still waits for dispatch.
    assert repo.ready_human_approvals(now, kinds=ALL_KINDS, limit=20) == [
        (wrong_hash.approval_id, wrong_hash_draft.draft_id)
    ]
    assert ApprovalService(repo, now=lambda: now).ready_human_count() == 1

    result = service.revoke(
        items=[
            (unknown_draft.draft_id, unknown_draft.payload_hash),
            (policy_draft.draft_id, policy_draft.payload_hash),
        ],
        actor=HUMAN,
    )
    assert [item["status"] for item in result["results"]] == ["failed", "failed"]
    assert result["revoked"] == []


def test_postgres_execution_page_groups_each_status_into_phases(postgres_url: str) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    clock = [dt.datetime.now(dt.UTC)]
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])
    policy = ApprovalService(
        repo, now=lambda: clock[0], auto_approve_kinds=frozenset({IntentKind.ARCHIVE})
    )
    short = dt.timedelta(minutes=10)
    drafts: dict[str, Draft] = {}

    def human(
        name: str,
        *,
        kind: IntentKind = IntentKind.TRASH,
        legacy_expiry: dt.timedelta | None = None,
        state: ExecutionState | None = None,
    ) -> None:
        clock[0] += dt.timedelta(milliseconds=1)
        draft = drafts[name] = _prepare(service, kind=kind)
        approval = _approve(service, draft)
        if state is not None:
            _claim(repo, approval, draft, clock[0])
            if state is not ExecutionState.ATTEMPTING:
                _settle(repo, approval, clock[0], state, error_class="ProviderNotAttempted")
        if legacy_expiry is not None:
            # A pre-durable-model approval that migration 006 left finished rows with.
            with psycopg.connect(postgres_url) as conn:
                conn.execute(
                    "UPDATE approvals SET expires_at=%s WHERE approval_id=%s",
                    (clock[0] + legacy_expiry, approval.approval_id),
                )
        if name == "consumed":
            repo.consume(approval.approval_id, draft.draft_id, draft.payload_hash, clock[0])
        if name == "revoked":
            repo.revoke_approvals([(draft.draft_id, draft.payload_hash)], now=clock[0])

    def automatic(name: str, approval_lifetime: dt.timedelta) -> None:
        clock[0] += dt.timedelta(milliseconds=1)
        drafts[name] = _prepare(
            policy, kind=IntentKind.ARCHIVE, approval_lifetime=approval_lifetime
        )

    human("approved")
    automatic("awaiting_client", dt.timedelta(minutes=60))
    automatic("client_expired", short)
    human("retryable", state=ExecutionState.RETRYABLE)
    human("approval_expired", legacy_expiry=short)
    human("expired_retryable", legacy_expiry=short, state=ExecutionState.RETRYABLE)
    human("revoked")
    human("attempting", kind=IntentKind.MOVE, state=ExecutionState.ATTEMPTING)
    human("confirmed", kind=IntentKind.SEND, state=ExecutionState.CONFIRMED)
    human("failed", kind=IntentKind.MARK, state=ExecutionState.FAILED)
    human("unknown", kind=IntentKind.ARCHIVE, state=ExecutionState.UNKNOWN)
    human("consumed")
    clock[0] += short + dt.timedelta(minutes=1)
    names = {draft.draft_id: name for name, draft in drafts.items()}

    expected = {
        "all": set(drafts),
        "pending": set(),
        "running": {"approved", "awaiting_client", "retryable", "attempting", "unknown"},
        "confirmed": {"confirmed"},
        "failed": {
            "client_expired",
            "failed",
            "consumed",
            "approval_expired",
            "expired_retryable",
            "revoked",
        },
    }
    for status, members in expected.items():
        page = service.execution_page(limit=50, offset=0, status=status)
        assert page["has_more"] is False
        assert [names[item["draft_id"]] for item in page["drafts"]] == [
            name for name in reversed(drafts) if name in members
        ], status
        if status != "all" and members:
            assert {item["phase"] for item in page["drafts"]} == {status}

    items = {
        names[item["draft_id"]]: item
        for item in service.execution_page(limit=50, offset=0)["drafts"]
    }
    assert {name: item["status"] for name, item in items.items()} == {
        "approved": "approved",
        "awaiting_client": "awaiting_client",
        "client_expired": "client_expired",
        "retryable": "retryable",
        "approval_expired": "approval_expired",
        "expired_retryable": "approval_expired",
        "revoked": "revoked",
        "attempting": "attempting",
        "confirmed": "confirmed",
        "failed": "failed",
        "unknown": "unknown",
        "consumed": "consumed",
    }
    assert {name for name, item in items.items() if item["revocable"]} == {
        "approved",
        "retryable",
    }
    assert service.execution_page(limit=1, offset=0)["counts"] == {
        "all": 12,
        "pending": 0,
        "running": 5,
        "confirmed": 1,
        "failed": 6,
    }
    assert {name for name, item in items.items() if item["approval"]["source"] == "policy"} == {
        "awaiting_client",
        "client_expired",
    }
    assert {name: item["kind"] for name, item in items.items() if item["kind"] != "trash"} == {
        "awaiting_client": "archive",
        "client_expired": "archive",
        "attempting": "move",
        "confirmed": "send",
        "failed": "mark",
        "unknown": "archive",
    }
    assert (items["retryable"]["attempt"], items["retryable"]["error_class"]) == (
        1,
        "ProviderNotAttempted",
    )
    assert items["approved"]["attempt"] is None

    first = service.execution_page(limit=3, offset=0, status="running")
    second = service.execution_page(limit=3, offset=3, status="running")
    assert first["has_more"] is True and second["has_more"] is False
    assert [names[item["draft_id"]] for item in first["drafts"] + second["drafts"]] == [
        "unknown",
        "attempting",
        "retryable",
        "awaiting_client",
        "approved",
    ]
    with pytest.raises(ApprovalError, match="unknown execution status filter"):
        service.execution_page(limit=1, offset=0, status="waiting' OR TRUE --")


def test_postgres_row_bound_drops_settled_history_before_open_work(
    postgres_url: str, monkeypatch
) -> None:
    # Truncating the UI snapshot must never hide a waiting approval or a
    # pending draft, no matter how old: only settled history may fall off.
    apply_migrations(postgres_url, MIGRATIONS)
    clock = [dt.datetime.now(dt.UTC)]
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])
    waiting_draft = _prepare(service)
    waiting = _approve(service, waiting_draft)
    for _ in range(6):
        clock[0] += dt.timedelta(milliseconds=1)
        draft = _prepare(service)
        approval = _approve(service, draft)
        _claim(repo, approval, draft, clock[0])
        _settle(repo, approval, clock[0], ExecutionState.CONFIRMED)
    clock[0] += dt.timedelta(milliseconds=1)
    pending = _prepare(service)
    monkeypatch.setattr(PostgresApprovalRepository, "UI_ROWS_BOUND", 4)
    rows = repo.approval_rows(clock[0])
    assert len(rows) == 4
    open_ids = {
        row.approval.approval_id for row in rows if row.approval is not None and row.state is None
    }
    assert waiting.approval_id in open_ids
    assert pending.draft_id in {row.draft.draft_id for row in rows if row.approval is None}
    assert service.ready_human_count() == 1
    assert [item["draft_id"] for item in service.pending_trash_selection()] == [pending.draft_id]


def test_postgres_pending_drafts_final_failures_queue_position_and_activity(
    postgres_url: str,
) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    clock = [dt.datetime.now(dt.UTC)]
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])

    def approved(state: ExecutionState | None = None, error_class: str | None = None):
        clock[0] += dt.timedelta(milliseconds=1)
        draft = _prepare(service)
        approval = _approve(service, draft)
        if state is not None:
            _claim(repo, approval, draft, clock[0])
            if state is not ExecutionState.ATTEMPTING:
                _settle(repo, approval, clock[0], state, error_class=error_class)
        return draft, approval

    first_draft, _first = approved()
    second_draft, _second = approved()
    gone_draft, _ = approved(ExecutionState.FAILED, "ProviderSourceGone")
    unverified_draft, _ = approved(ExecutionState.FAILED, "OutcomeUnverified")
    retryable_draft, _ = approved(ExecutionState.FAILED, "ProviderDefinitelyRejected")
    approved(ExecutionState.CONFIRMED)
    current_draft, _ = approved(ExecutionState.ATTEMPTING)
    clock[0] += dt.timedelta(milliseconds=1)
    unapproved = _prepare(service)
    _prepare(service, lifetime=dt.timedelta(seconds=-1))  # Abandoned: never listed.

    pending = service.execution_page(limit=10, offset=0, status="pending")
    assert [(i["draft_id"], i["status"], i["approval"]) for i in pending["drafts"]] == [
        (unapproved.draft_id, "pending_approval", None)
    ]
    assert pending["counts"] == {
        "all": 8,
        "pending": 1,
        "running": 3,
        "confirmed": 1,
        "failed": 3,
    }
    failed = {
        item["draft_id"]: item["revocable"]
        for item in service.execution_page(limit=10, offset=0, status="failed")["drafts"]
    }
    # Every FAILED outcome is final; none can be revoked or replayed.
    assert failed == {
        gone_draft.draft_id: False,
        unverified_draft.draft_id: False,
        retryable_draft.draft_id: False,
    }
    outcome = service.revoke(
        items=[(d.draft_id, d.payload_hash) for d in (gone_draft, unverified_draft)],
        actor=HUMAN,
    )
    assert outcome["revoked"] == []

    # The dispatcher serves waiting human approvals oldest-approval first.
    assert service.review(first_draft.draft_id)["queue_position"] == 1
    assert service.review(second_draft.draft_id)["queue_position"] == 2
    assert service.review(first_draft.draft_id)["phase"] == "running"
    assert service.review(gone_draft.draft_id)["queue_position"] is None
    activity = service.dispatch_activity()
    assert activity["current"]["draft_id"] == current_draft.draft_id
    assert activity["current"]["kind"] == "trash"
    # CONFIRMED plus three FAILED human executions finished inside the window.
    assert (activity["finished_recent"], activity["window_minutes"]) == (4, 10)
    clock[0] += dt.timedelta(minutes=11)
    assert service.dispatch_activity()["finished_recent"] == 0


def test_postgres_dispatcher_executes_human_approvals_of_every_kind_and_never_replays(
    postgres_url: str,
) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    key = generate_key()
    clock = [dt.datetime.now(dt.UTC)]
    repo = PostgresApprovalRepository(postgres_url, key=key, host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])
    policy = ApprovalService(
        repo, now=lambda: clock[0], auto_approve_kinds=frozenset({IntentKind.ARCHIVE})
    )
    # Late human approvals keep a full window after their drafts expire.
    late_drafts = [
        _prepare(service, kind=kind, lifetime=dt.timedelta(seconds=1)) for kind in IntentKind
    ]
    for draft in late_drafts:
        clock[0] += dt.timedelta(milliseconds=1)
        _approve(service, draft)
    revoked_draft = _prepare(service)
    _approve(service, revoked_draft)
    repo.revoke_approvals([(revoked_draft.draft_id, revoked_draft.payload_hash)], now=clock[0])
    policy_draft = _prepare(policy, kind=IntentKind.ARCHIVE)
    _prepare(service)
    clock[0] += dt.timedelta(minutes=2)
    assert len(repo.ready_human_approvals(clock[0], kinds=ALL_KINDS, limit=10)) == 5
    trash_only = repo.ready_human_approvals(clock[0], kinds=frozenset({IntentKind.TRASH}), limit=10)
    assert [draft_id for _, draft_id in trash_only] == [late_drafts[-1].draft_id]

    uncertain_message = late_drafts[-1].payload["stable_message_id"]
    calls: list[str] = []

    def provider(payload: dict, _key: str) -> dict:
        calls.append(payload["operation"])
        if payload.get("stable_message_id") == uncertain_message:
            raise ProviderOutcomeUnknown("provider may have moved message")
        return {}

    restored = ApprovalService(
        PostgresApprovalRepository(postgres_url, key=key, host_id="host-a"), now=lambda: clock[0]
    )
    dispatcher = ApprovalDispatcher(
        restored, _executor(restored, provider), kinds=ALL_KINDS, host="host-a"
    )
    assert dispatcher.run_once(limit=1) == {"confirmed": 1}
    assert dispatcher.run_once() == {"confirmed": 3, "unknown": 1}
    assert dispatcher.last_item_error_class == "ProviderOutcomeUnknown"
    restarted = ApprovalDispatcher(restored, dispatcher.execute, kinds=ALL_KINDS, host="host-a")
    assert restarted.run_once() == {}
    assert calls == [kind.value for kind in IntentKind]
    policy_approval = repo.get_approval_for_draft(policy_draft.draft_id)
    assert policy_approval.approval_source is ApprovalSource.POLICY
    assert repo.get_execution_for_approval(policy_approval.approval_id) is None

    page = restored.execution_page(limit=2, offset=0)
    assert len(page["drafts"]) == 2 and page["has_more"]
    all_items = restored.execution_page(limit=10, offset=0)["drafts"]
    assert sorted(item["status"] for item in all_items) == sorted(
        ["confirmed"] * 4 + ["unknown", "revoked", "awaiting_client", "pending_approval"]
    )
    uncertain = next(item for item in all_items if item["status"] == "unknown")
    assert uncertain["summary"]["stable_message_id"] == uncertain_message
    blocked_draft = _prepare(restored, stable_id=uncertain_message)
    _approve(restored, blocked_draft)
    clock[0] += dt.timedelta(seconds=1)
    _approve(restored, _prepare(restored))
    assert dispatcher.run_once(limit=1) == {"blocked": 1, "confirmed": 1}
    assert len(calls) == len(IntentKind) + 1
    blocked = next(
        item
        for item in restored.execution_page(limit=10, offset=0)["drafts"]
        if item["draft_id"] == blocked_draft.draft_id
    )
    assert (blocked["status"], blocked["reason_code"]) == ("blocked", "PROVIDER_OUTCOME_UNKNOWN")


def test_postgres_dispatcher_retries_not_attempted_after_backoff_until_revoked(
    postgres_url: str,
) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    clock = [dt.datetime.now(dt.UTC)]
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])
    unreachable: set[str] = set()
    calls: list[str] = []

    def provider(payload: dict, _key: str) -> dict:
        calls.append(payload["stable_message_id"])
        if payload["stable_message_id"] in unreachable:
            unreachable.discard(payload["stable_message_id"])
            raise ProviderNotAttempted("IMAP login failed before any mailbox command")
        return dict(CONFIRMED_RESULT)

    execute = _executor(service, provider)
    dispatcher = ApprovalDispatcher(service, execute, kinds=ALL_KINDS, host="host-a")

    backoff_draft = _prepare(service)
    backoff = _approve(service, backoff_draft)
    unreachable.add(backoff_draft.payload["stable_message_id"])
    assert dispatcher.run_once() == {"retryable": 1}
    assert dispatcher.last_item_error_class == "ProviderNotAttempted"
    execution = repo.get_execution_for_approval(backoff.approval_id)
    assert (execution.state, execution.attempt, execution.error_class) == (
        ExecutionState.RETRYABLE,
        1,
        "ProviderNotAttempted",
    )
    assert service.review(backoff_draft.draft_id)["status"] == "retryable"
    clock[0] += dt.timedelta(seconds=59)
    assert dispatcher.run_once() == {}
    clock[0] += dt.timedelta(seconds=1)
    assert dispatcher.run_once() == {"confirmed": 1}
    execution = repo.get_execution_for_approval(backoff.approval_id)
    assert (execution.state, execution.attempt) == (ExecutionState.CONFIRMED, 2)
    assert len(calls) == 2

    stopped_draft = _prepare(service)
    stopped = _approve(service, stopped_draft)
    unreachable.add(stopped_draft.payload["stable_message_id"])
    assert dispatcher.run_once() == {"retryable": 1}
    # The durable approval never lapses; revoking it is what stops the retries.
    clock[0] += dt.timedelta(days=2)
    repo.revoke_approvals([(stopped_draft.draft_id, stopped_draft.payload_hash)], now=clock[0])
    assert dispatcher.run_once() == {}
    assert service.review(stopped_draft.draft_id)["status"] == "revoked"
    with pytest.raises(ApprovalError, match="APPROVAL_CLOSED_BEFORE_PROVIDER_REACHED"):
        execute(
            approval_id=stopped.approval_id,
            draft_id=stopped_draft.draft_id,
            current_payload=stopped_draft.payload,
            expected_kind=IntentKind.TRASH,
        )
    assert len(calls) == 3


class _ReconcilingProvider:
    def __init__(self) -> None:
        self.executed: list[str] = []
        self.reconciled: list[str] = []
        self.inconclusive: set[str] = set()

    def execute(self, _payload: dict, idempotency_key: str) -> dict:
        self.executed.append(idempotency_key)
        return dict(CONFIRMED_RESULT)

    def reconcile(self, _payload: dict, idempotency_key: str) -> dict | None:
        self.reconciled.append(idempotency_key)
        if idempotency_key in self.inconclusive:
            return None
        return {**CONFIRMED_RESULT, "reconciled": True}


def test_postgres_reconcile_sweep_resolves_stale_attempts_without_replay_and_backs_off_unknown(
    postgres_url: str,
) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    t0 = dt.datetime.now(dt.UTC)
    clock = [t0]
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])
    policy = ApprovalService(
        repo, now=lambda: clock[0], auto_approve_kinds=frozenset({IntentKind.ARCHIVE})
    )
    provider = _ReconcilingProvider()
    dispatcher = ApprovalDispatcher(
        service, _executor(service, provider), kinds=ALL_KINDS, host="host-a"
    )

    def interrupted(draft: Draft, approval, state=None, error_class=None):
        execution = _claim(repo, approval, draft, t0)
        if state is not None:
            _settle(repo, approval, t0, state, error_class=error_class)
        return execution

    human_draft = _prepare(service)
    human = _approve(service, human_draft)
    crashed = interrupted(human_draft, human)
    policy_draft = _prepare(policy, kind=IntentKind.ARCHIVE)
    policy_approval = repo.get_approval_for_draft(policy_draft.draft_id)
    policy_crashed = interrupted(policy_draft, policy_approval)
    # SEND is never replayed, so an inconclusive reconcile keeps backing off.
    unknown_draft = _prepare(service, kind=IntentKind.SEND)
    unknown = _approve(service, unknown_draft)
    uncertain = interrupted(unknown_draft, unknown, ExecutionState.UNKNOWN, "TimeoutError")
    partial_draft = _prepare(service)
    partial = _approve(service, partial_draft)
    interrupted(partial_draft, partial, ExecutionState.UNKNOWN, "ProviderPartialOutcome")
    failed_draft = _prepare(service)
    failed = _approve(service, failed_draft)
    interrupted(failed_draft, failed, ExecutionState.FAILED, "ProviderDefinitelyRejected")
    provider.inconclusive.add(uncertain.idempotency_key)

    clock[0] = t0 + service.stale_execution_after - ONE_MICROSECOND
    assert dispatcher.reconcile_once() == {}
    clock[0] = t0 + service.stale_execution_after
    # Interrupted rows of either approval source are resolved read-only.
    assert dispatcher.reconcile_once() == {"reconciled": 2}
    for approval in (human, policy_approval):
        execution = repo.get_execution_for_approval(approval.approval_id)
        assert (execution.state, execution.attempt) == (ExecutionState.CONFIRMED, 1)
        assert execution.provider_result["reconciled"] is True

    clock[0] = t0 + UNKNOWN_RECONCILE_INTERVAL - ONE_MICROSECOND
    assert dispatcher.reconcile_once() == {}
    clock[0] = t0 + UNKNOWN_RECONCILE_INTERVAL
    assert dispatcher.reconcile_once() == {"reconcile_inconclusive": 1}
    execution = repo.get_execution_for_approval(unknown.approval_id)
    assert (execution.state, execution.error_class, execution.updated_at) == (
        ExecutionState.UNKNOWN,
        "TimeoutError",
        clock[0],
    )
    bumped = clock[0]
    clock[0] = bumped + UNKNOWN_RECONCILE_INTERVAL - ONE_MICROSECOND
    assert dispatcher.reconcile_once() == {}
    provider.inconclusive.clear()
    clock[0] = bumped + UNKNOWN_RECONCILE_INTERVAL
    assert dispatcher.reconcile_once() == {"reconciled": 1}
    assert repo.get_execution_for_approval(unknown.approval_id).state is ExecutionState.CONFIRMED

    partial_execution = repo.get_execution_for_approval(partial.approval_id)
    assert (partial_execution.state, partial_execution.updated_at) == (ExecutionState.UNKNOWN, t0)
    assert repo.get_execution_for_approval(failed.approval_id).state is ExecutionState.FAILED
    assert provider.executed == []
    assert sorted(provider.reconciled) == sorted(
        [
            crashed.idempotency_key,
            policy_crashed.idempotency_key,
            uncertain.idempotency_key,
            uncertain.idempotency_key,
        ]
    )


def test_postgres_dispatcher_heartbeat_is_one_row_updated_by_each_scan(postgres_url: str) -> None:
    apply_migrations(postgres_url, MIGRATIONS)
    clock = [dt.datetime.now(dt.UTC)]
    repo = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    service = ApprovalService(repo, now=lambda: clock[0])
    assert repo.dispatcher_status() is None
    _approve(service, _prepare(service))
    dispatcher = ApprovalDispatcher(
        service,
        _executor(service, lambda *_: dict(CONFIRMED_RESULT)),
        kinds=frozenset({IntentKind.TRASH, IntentKind.ARCHIVE}),
        host="host-a",
    )

    async def first_heartbeat() -> dict:
        stop = asyncio.Event()
        task = asyncio.create_task(dispatcher.run(stop))
        try:
            async with asyncio.timeout(10):
                while (status := await asyncio.to_thread(repo.dispatcher_status)) is None:
                    await asyncio.sleep(0.02)
        finally:
            stop.set()
            await task
        return status

    first = asyncio.run(first_heartbeat())
    assert {key: value for key, value in first.items() if key != "updated_at"} == {
        "host": "host-a",
        "kinds": ["archive", "trash"],
        "last_scan_at": clock[0],
        "last_error_class": None,
        "last_item_error_class": None,
        "last_result": {"confirmed": 1},
    }

    later = clock[0] + dt.timedelta(seconds=2)
    repo.record_dispatcher_status(
        host="host-a",
        kinds=[],
        last_scan_at=later,
        last_error_class="OperationalError",
        last_item_error_class="WriterLeaseUnavailable",
        last_result={},
    )
    second = repo.dispatcher_status()
    assert {key: value for key, value in second.items() if key != "updated_at"} == {
        "host": "host-a",
        "kinds": [],
        "last_scan_at": later,
        "last_error_class": "OperationalError",
        "last_item_error_class": "WriterLeaseUnavailable",
        "last_result": {},
    }
    assert second["updated_at"] >= first["updated_at"]
    with psycopg.connect(postgres_url) as conn:
        assert conn.execute("SELECT count(*) FROM approval_dispatcher_status").fetchone()[0] == 1


def _batch_test_drafts(repository, count=526):
    now = dt.datetime.now(dt.UTC)
    drafts = [
        Draft(
            draft_id=str(uuid.uuid4()),
            kind=IntentKind.TRASH,
            payload={"subject": f"Message {index}", "account": "gmail", "body": "x" * 20000},
            payload_hash=f"{index:064x}",
            created_by="agent",
            created_client="codex",
            created_at=now + dt.timedelta(microseconds=index),
            expires_at=now + dt.timedelta(hours=2),
        )
        for index in range(count)
    ]
    with psycopg.connect(repository.database_url) as conn:
        with conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO approval_drafts(
                    draft_id,kind,payload_hash,encrypted_payload,created_by,client_id,
                    created_at,expires_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                [
                    (
                        draft.draft_id,
                        draft.kind.value,
                        draft.payload_hash,
                        repository._encrypt(draft),
                        draft.created_by,
                        draft.created_client,
                        draft.created_at,
                        draft.expires_at,
                    )
                    for draft in drafts
                ],
            )
    return drafts


def test_postgres_526_batch_selection_and_approval_use_constant_connections(
    postgres_url,
    monkeypatch,
):
    apply_migrations(postgres_url, Path("migrations"))
    repository = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="batch-test")
    service = ApprovalService(repository)
    drafts = _batch_test_drafts(repository)
    original_connect = psycopg.connect
    connections = []

    def counted_connect(*args, **kwargs):
        connections.append(True)
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(psycopg, "connect", counted_connect)
    page = service.pending_trash_page(limit=50, offset=0)
    # One bounded query for the pending rows and one for the 50 displayed
    # payloads — constant regardless of how many drafts are pending.
    assert len(connections) == 2
    assert page["has_more"] and len(page["drafts"]) == 50
    assert all(
        item["review_packet"] is None and "body" not in item["summary"] for item in page["drafts"]
    )
    connections.clear()
    selected = service.pending_trash_selection()
    assert len(connections) == 1 and len(selected) == 526
    assert all(set(item) == {"draft_id", "payload_hash"} for item in selected)
    connections.clear()
    actor = Actor("admin", "approval-ui", "approval-ui", True)
    results = []
    for offset in range(0, 526, 200):
        chunk = selected[offset : offset + 200]
        results.extend(
            service.approve_batch(
                items=[(item["draft_id"], item["payload_hash"]) for item in chunk],
                actor=actor,
            )
        )
    assert len(connections) == 6
    assert all(item["status"] == "approved" for item in results)
    assert {item["draft_id"] for item in results} == {draft.draft_id for draft in drafts}
    for item in results:
        # Human batch approvals are durable work orders without an expiry.
        assert item["approval"].expires_at is None
    assert service.pending_trash_selection() == []
    with original_connect(postgres_url) as conn:
        assert conn.execute("SELECT count(*) FROM approvals").fetchone()[0] == 526
        assert conn.execute("SELECT count(*) FROM mail_action_ledger").fetchone()[0] == 0


def test_postgres_batch_keeps_partial_results_for_invalid_expired_and_corrupt_packets(postgres_url):
    apply_migrations(postgres_url, Path("migrations"))
    repository = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="batch-test")
    service = ApprovalService(repository)
    good, changed, expired, corrupt, wrong_kind = _batch_test_drafts(repository, 5)
    with psycopg.connect(postgres_url) as conn:
        conn.execute(
            "UPDATE approval_drafts SET expires_at=now()-interval '1 minute' WHERE draft_id=%s",
            (expired.draft_id,),
        )
        conn.execute(
            "UPDATE approval_drafts SET encrypted_payload=%s WHERE draft_id=%s",
            (b"broken", corrupt.draft_id),
        )
        conn.execute(
            "UPDATE approval_drafts SET kind='mark' WHERE draft_id=%s", (wrong_kind.draft_id,)
        )
    items = [
        (good.draft_id, good.payload_hash),
        (changed.draft_id, "wrong"),
        (expired.draft_id, expired.payload_hash),
        (corrupt.draft_id, corrupt.payload_hash),
        (wrong_kind.draft_id, wrong_kind.payload_hash),
        ("invalid-uuid", "hash"),
        (str(uuid.uuid4()), "hash"),
    ]
    results = service.approve_batch(
        items=items, actor=Actor("admin", "approval-ui", "approval-ui", True)
    )
    assert [item["draft_id"] for item in results] == [item[0] for item in items]
    assert [item["status"] for item in results] == ["approved"] + ["failed"] * 6
    assert "changed" in results[1]["detail"]
    assert "expired" in results[2]["detail"]
    assert "malformed" in results[3]["detail"]
    assert "only supports trash" in results[4]["detail"]
    assert results[5]["detail"] == results[6]["detail"] == "draft not found"
    with psycopg.connect(postgres_url) as conn:
        assert conn.execute("SELECT count(*) FROM approvals").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM mail_action_ledger").fetchone()[0] == 0


def test_postgres_overlapping_reverse_batches_issue_one_approval_each(postgres_url):
    apply_migrations(postgres_url, Path("migrations"))
    key = generate_key()
    barrier = threading.Barrier(2)

    class SimultaneousRepository(PostgresApprovalRepository):
        def get_drafts_batch(self, draft_ids):
            drafts = super().get_drafts_batch(draft_ids)
            barrier.wait(timeout=10)
            return drafts

    repositories = [
        SimultaneousRepository(postgres_url, key=key, host_id="batch-test") for _ in range(2)
    ]
    drafts = _batch_test_drafts(repositories[0], 100)
    actor = Actor("admin", "approval-ui", "approval-ui", True)

    def submit(index):
        ordered = drafts if index == 0 else list(reversed(drafts))
        return ApprovalService(repositories[index]).approve_batch(
            items=[(draft.draft_id, draft.payload_hash) for draft in ordered],
            actor=actor,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, range(2)))
    combined = [item for batch in results for item in batch]
    for draft in drafts:
        assert sorted(
            item["status"] for item in combined if item["draft_id"] == draft.draft_id
        ) == ["already_approved", "approved"]
    with psycopg.connect(postgres_url) as conn:
        assert conn.execute("SELECT count(*) FROM approvals").fetchone()[0] == 100


def test_postgres_batch_lock_wait_is_bounded(postgres_url):
    apply_migrations(postgres_url, Path("migrations"))
    repository = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="batch-test")
    service = ApprovalService(repository)
    draft = _batch_test_drafts(repository, 1)[0]
    with psycopg.connect(postgres_url) as blocker:
        blocker.execute(
            """INSERT INTO approvals(approval_id,draft_id,payload_hash,approved_by,approved_client,approved_at,expires_at)
               VALUES (%s,%s,%s,'admin','approval-ui',now(),now()+interval '30 minutes')""",
            (str(uuid.uuid4()), draft.draft_id, draft.payload_hash),
        )
        started = time.perf_counter()
        with pytest.raises(psycopg.errors.LockNotAvailable):
            service.approve_batch(
                items=[(draft.draft_id, draft.payload_hash)],
                actor=Actor("admin", "approval-ui", "approval-ui", True),
            )
        assert time.perf_counter() - started < 10
        blocker.rollback()
    # The timed-out transaction did not commit a partial batch; retry is possible.
    result = service.approve_batch(
        items=[(draft.draft_id, draft.payload_hash)],
        actor=Actor("admin", "approval-ui", "approval-ui", True),
    )
    assert result[0]["status"] == "approved"


def test_postgres_location_diagnostics_decrypt_only_identities_and_keep_unknown(postgres_url):
    from evergarden.approvals.models import Approval, ApprovalSource

    apply_migrations(postgres_url, Path(__file__).resolve().parents[1] / "migrations")
    now = dt.datetime.now(dt.UTC)
    repository = PostgresApprovalRepository(postgres_url, key=generate_key(), host_id="host-a")
    draft = Draft(
        draft_id=str(uuid.uuid4()),
        kind=IntentKind.ARCHIVE,
        payload={
            "stable_message_id": "a" * 24,
            "source_folder": "INBOX",
            "destination": "Archive",
            "body_text": "private diagnostic sentinel",
        },
        payload_hash="f" * 64,
        created_by="user",
        created_client="client",
        created_at=now,
        expires_at=now + dt.timedelta(hours=1),
    )
    repository.add_draft(draft)
    approval = Approval(
        approval_id=str(uuid.uuid4()),
        draft_id=draft.draft_id,
        payload_hash=draft.payload_hash,
        approved_by="admin",
        approved_client="approval-ui",
        approved_at=now,
        expires_at=now + dt.timedelta(hours=1),
        approval_source=ApprovalSource.HUMAN,
    )
    repository.add_approval(approval)
    repository.claim_execution(
        approval_id=approval.approval_id,
        draft_id=draft.draft_id,
        kind=draft.kind,
        payload_hash=draft.payload_hash,
        now=now,
    )
    repository.transition_execution(
        approval.approval_id,
        expected=frozenset({ExecutionState.ATTEMPTING}),
        state=ExecutionState.UNKNOWN,
        now=now,
    )
    summaries = repository.location_execution_summaries()
    assert summaries["a" * 24][0]["state"] == "UNKNOWN"
    assert summaries["a" * 24][0]["source_folder"] == "INBOX"
    assert "private diagnostic sentinel" not in str(summaries)
    assert "body_text" not in str(summaries)
    assert (
        repository.get_execution_for_approval(approval.approval_id).state is ExecutionState.UNKNOWN
    )
