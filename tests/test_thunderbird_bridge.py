from __future__ import annotations

import base64
import datetime as dt
import json
import sqlite3
import zipfile
from io import BytesIO

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from apps.mail_ui.bridge import addon_bytes, install_bridge_routes
from evergarden.archive.sqlite_archive import ArchiveReader
from evergarden.auth.credential_store import encode_key, generate_key
from evergarden.config import Settings
from evergarden.mail.models import AccountConfig, load_account_configs
from evergarden.mail.thunderbird_bridge import BridgeClients, BridgeError, BridgeMailbox


@pytest.fixture
def setup_bridge(tmp_path):
    account = AccountConfig(
        alias="work",
        address="user@work.test",
        imap_host="imap.gmail.com",
        smtp_host="smtp.gmail.com",
        credential_record="google:work",
        send_from_addresses=("user@work.test",),
        enabled=False,
    )
    import dataclasses

    accounts = tmp_path / "accounts.json"
    accounts.write_text(
        json.dumps({"schema_version": 1, "accounts": [dataclasses.asdict(account)]})
    )
    accounts.chmod(0o600)
    key = generate_key()
    key_file = tmp_path / "key"
    key_file.write_text(encode_key(key))
    key_file.chmod(0o600)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=tmp_path / "mcp-token",
        admin_session_key_file=tmp_path / "admin-key",
        admin_credential_file=tmp_path / "admin-credentials",
        account_config_file=accounts,
        thunderbird_bridge_accounts="work",
        thunderbird_bridge_clients_file=tmp_path / "clients.json",
        archive_dir=tmp_path / "archive",
        credential_key_file=key_file,
    )
    clients = BridgeClients(settings)
    config = clients.pair("work")
    return settings, clients, config, key


def payload(config, index=1, notify=True):
    raw = (
        f"From: Sender <sender@example.test>\r\nTo: user@work.test\r\nSubject: Test {index}\r\n"
        f"Message-ID: <bridge-{index}@example.test>\r\nDate: Fri, 9 Oct 2026 10:00:00 +0000\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\nHello bridge"
    ).encode()
    return {
        "account": config["account"],
        "address": config["address"],
        "raw_base64": base64.b64encode(raw).decode(),
        "notify": notify,
        "read": False,
    }


def test_pair_scope_rotation_expiry_and_private_storage(setup_bridge):
    settings, clients, config, _ = setup_bridge
    assert clients.authenticate(config["token"])["account"] == "work"
    assert config["token"] not in settings.thunderbird_bridge_clients_file.read_text()
    assert settings.thunderbird_bridge_clients_file.stat().st_mode & 0o077 == 0
    assert load_account_configs(settings.account_config_file) == ()
    with pytest.raises(BridgeError):
        clients.pair("other")
    replacement = clients.pair("work")
    with pytest.raises(BridgeError):
        clients.authenticate(config["token"])
    with clients.store.lock():
        value = clients._read()
        value["clients"][0]["expires_at"] = (
            dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
        ).isoformat()
        clients.store.write_json(value)
    with pytest.raises(BridgeError):
        clients.authenticate(replacement["token"])
    final = clients.pair("work")
    clients.revoke("work")
    with pytest.raises(BridgeError):
        clients.authenticate(final["token"])


def test_receive_retries_crash_repair_and_no_provider_locators(setup_bridge, monkeypatch):
    settings, clients, config, key = setup_bridge
    mailbox = BridgeMailbox(settings.archive_dir, attachment_key=key)
    client = clients.authenticate(config["token"])
    imported = mailbox.archive.import_unlocated_records

    def crash_after_archive(records):
        imported(records)
        raise RuntimeError("simulated lost process")

    monkeypatch.setattr(mailbox.archive, "import_unlocated_records", crash_after_archive)
    with pytest.raises(RuntimeError):
        mailbox.receive(client, payload(config))
    assert mailbox.notifications()["unread_count"] == 0
    monkeypatch.setattr(mailbox.archive, "import_unlocated_records", imported)
    accepted = mailbox.receive(client, payload(config))
    assert accepted["duplicate"] is False
    assert mailbox.receive(client, payload(config))["duplicate"] is True
    assert mailbox.notifications()["unread_count"] == 1
    reader = ArchiveReader(settings.archive_dir, attachment_key=key)
    assert reader.get_message(accepted["message_id"])["body_text"] == "Hello bridge"
    assert reader.message_locations(accepted["message_id"]) == []
    with sqlite3.connect(mailbox.archive.hot_path) as db:
        assert db.execute("SELECT count(*) FROM provider_uid_observations").fetchone()[0] == 0
    with pytest.raises(BridgeError):
        mailbox.receive(client, {**payload(config), "account": "other"})
    with pytest.raises(BridgeError):
        mailbox.receive(client, {**payload(config), "raw_base64": "%%%="})


def test_notification_pagination_ack_boundary_and_silent_backfill(setup_bridge):
    settings, clients, config, key = setup_bridge
    mailbox = BridgeMailbox(settings.archive_dir, attachment_key=key)
    client = clients.authenticate(config["token"])
    mailbox.receive(client, payload(config, 0, notify=False))
    for index in range(1, 54):
        mailbox.receive(client, payload(config, index))
    first = mailbox.notifications()
    assert len(first["items"]) == 50 and first["has_more"]
    mailbox.acknowledge(first["cursor"])
    second = mailbox.notifications(after=first["cursor"])
    assert len(second["items"]) == 3 and not second["has_more"]
    assert second["unread_count"] == 3
    assert all(item["read_at"] is None for item in second["items"])
    mailbox.heartbeat("work", pending=3, state="retrying")
    assert mailbox.status(clients.accounts())[0]["online"]


def test_http_auth_before_payload_pair_csrf_and_addon(setup_bridge):
    settings, _, _, _ = setup_bridge
    app = FastAPI()

    def identity(request):
        if request.headers.get("x-test-admin") != "yes":
            raise HTTPException(401)
        return "admin"

    def csrf(request, current):
        assert current == "admin"
        if request.headers.get("x-csrf-token") != "test-csrf":
            raise HTTPException(403)

    install_bridge_routes(app, settings, identity, csrf)
    client = TestClient(app)
    assert client.post("/bridge/ingest", content=b"not JSON").status_code == 401
    assert client.get("/bridge/notifications").status_code == 401
    assert (
        client.post(
            "/bridge/pair", json={"account": "work"}, headers={"x-test-admin": "yes"}
        ).status_code
        == 403
    )
    headers = {"x-test-admin": "yes", "x-csrf-token": "test-csrf"}
    config = client.post("/bridge/pair", json={"account": "work"}, headers=headers).json()
    ingest = {"Authorization": f"Bearer {config['token']}"}
    assert client.post("/bridge/ingest", json=payload(config), headers=ingest).status_code == 200
    assert client.get("/bridge/notifications", headers=ingest).status_code == 401
    assert client.get("/bridge/notifications?after=-1", headers=headers).status_code == 400
    assert (
        client.post(
            "/bridge/heartbeat", json={"pending": 0, "state": "connected"}, headers=ingest
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/bridge/notifications/read", json={"through": True}, headers=headers
        ).status_code
        == 400
    )
    assert (
        client.post("/bridge/revoke", json={"account": "work"}, headers=headers).status_code == 200
    )
    assert client.post("/bridge/ingest", json=payload(config), headers=ingest).status_code == 401
    with zipfile.ZipFile(BytesIO(addon_bytes())) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert "messagesRead" in manifest["permissions"]
        assert not {"messagesMove", "messagesDelete", "messagesUpdate", "messages.send"} & set(
            manifest["permissions"]
        )


@pytest.mark.parametrize("native_sync_enabled", [False, True])
def test_bridge_readable_but_never_native_write_account(setup_bridge, native_sync_enabled):

    import dataclasses

    from evergarden.approvals.service import ApprovalRepository, ApprovalService
    from evergarden.auth.models import Principal
    from evergarden.mail.runtime import MailRuntime
    from evergarden.mcp.tools import ToolRuntime

    settings, clients, config, key = setup_bridge
    mail = object.__new__(MailRuntime)
    mail.settings = settings
    native = AccountConfig(
        alias="native", address="native@example.test", imap_host="imap.example.test"
    )
    work = next(account for account in clients.accounts().values() if account.alias == "work")
    mail.accounts = (
        (native, dataclasses.replace(work, enabled=True)) if native_sync_enabled else (native,)
    )
    assert [account.alias for account in mail.read_accounts] == ["native", "work"]
    assert {account.alias for account in mail.accounts} == (
        {"native", "work"} if native_sync_enabled else {"native"}
    )
    assert mail.receive_only_accounts == frozenset({"work"})
    mailbox = BridgeMailbox(settings.archive_dir, attachment_key=key)
    receipt = mailbox.receive(clients.authenticate(config["token"]), payload(config))
    runtime = ToolRuntime(
        archive=ArchiveReader(settings.archive_dir, attachment_key=key),
        approvals=ApprovalService(
            ApprovalRepository(),
            accounts=mail.accounts,
            receive_only_accounts=mail.receive_only_accounts,
        ),
        execute_approved=lambda **kwargs: pytest.fail("must not execute"),
        accounts=mail.read_accounts,
        receive_only_accounts=mail.receive_only_accounts,
    )
    principal = Principal.build(
        subject="admin",
        client_id="test",
        scopes=["mail:read", "mail:draft"],
        audience="https://example.test/mcp",
        issuer="https://example.test",
    )
    accounts = runtime.call("list_accounts", {}, principal)
    assert accounts[1]["receive_only"] is True
    assert "receive_only" not in accounts[0]
    assert (
        runtime.call("get_message", {"message_id": receipt["message_id"]}, principal)["account"]
        == "work"
    )
    with pytest.raises(ValueError, match="receiving and notifications only"):
        runtime.call(
            "preview_trash",
            {"account": "work", "stable_message_id": receipt["message_id"]},
            principal,
        )
    with pytest.raises(ValueError, match="receiving and notifications only"):
        runtime.call(
            "prepare_send",
            {
                "account": "work",
                "to": ["recipient@example.test"],
                "subject": "test",
                "body": "test",
            },
            principal,
        )
    if not native_sync_enabled:
        return

    # Bridge ingestion and native IMAP sync share the (stable_id, account)
    # identity, so the same message arriving on both paths stays one record.
    from evergarden.archive.sqlite_archive import ArchiveWriter
    from evergarden.mail.sync import parse_message

    raw = base64.b64decode(payload(config)["raw_base64"])
    record = parse_message(account="work", folder="INBOX", uid=7, raw=raw, flags=("\\Seen",))
    assert record.stable_id == receipt["message_id"]
    writer = ArchiveWriter(settings.archive_dir, attachment_key=key)
    writer.upsert(record, uid_validity="777")

    # Native sync first, bridge second: the has_message guard skips the
    # archive import instead of failing the bridge receipt.
    second = parse_message(
        account="work",
        folder="INBOX",
        uid=8,
        raw=base64.b64decode(payload(config, index=2)["raw_base64"]),
        flags=(),
    )
    writer.upsert(second, uid_validity="777")
    second_receipt = mailbox.receive(
        clients.authenticate(config["token"]), payload(config, index=2)
    )
    assert second_receipt["accepted"] is True
    assert second_receipt["message_id"] == second.stable_id

    with sqlite3.connect(settings.archive_dir / "mail-hot.db") as conn:
        counts = dict(conn.execute("SELECT id, COUNT(*) FROM messages GROUP BY id").fetchall())
    assert counts == {record.stable_id: 1, second.stable_id: 1}


def test_enabling_native_sync_in_the_config_file_keeps_the_paired_bridge_working(setup_bridge):
    # Flipping enabled: true in the account file must not silently 401 the
    # paired add-on: the bridge stays an ingest path (receive-only is kept by
    # AccountPolicy) and dedup keeps the overlap one record.
    import dataclasses

    settings, clients, config, key = setup_bridge
    work = next(account for account in clients.accounts().values() if account.alias == "work")
    settings.account_config_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "accounts": [dataclasses.asdict(dataclasses.replace(work, enabled=True))],
            }
        )
    )
    client = clients.authenticate(config["token"])
    assert client["account"] == "work"
    assert clients.paired_accounts() == {"work"}
    mailbox = BridgeMailbox(settings.archive_dir, attachment_key=key)
    receipt = mailbox.receive(client, payload(config))
    assert receipt["accepted"] is True
