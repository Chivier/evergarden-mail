from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import io
import json
import sys
from pathlib import Path

import httpx
import pytest
from conftest import message_record
from fastapi.testclient import TestClient

from apps.mail_ui import main as mail_ui_module
from apps.mail_ui.main import (
    McpGateway,
    McpSyncIncomplete,
    McpToolError,
    McpTransportError,
    _private_token,
    create_app,
)
from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter
from evergarden.auth.admin_session import credential_document
from evergarden.auth.credential_store import CredentialStore, encode_key, generate_key
from evergarden.config import Settings
from evergarden.mail import credential_admin
from evergarden.mail.account_admin import (
    AccountAdminError,
    AccountConfigConflict,
    AccountConfigManager,
)
from evergarden.mail.models import load_account_configs
from evergarden.mail.preferences import (
    MailPreferenceConflict,
    MailPreferenceError,
    MailPreferenceStore,
)
from evergarden.mail.staged_attachments import (
    StagedAttachmentError,
    StagedAttachmentStore,
)
from evergarden.mail.verification import VerificationCodeError, find_verification_codes


def _account(alias: str = "work") -> dict:
    return {
        "alias": alias,
        "address": f"mailbox@{alias}.example",
        "send_from_addresses": [
            f"public-name@{alias}.example",
            f"mailbox@{alias}.example",
        ],
        "imap_host": "imap.example.com",
        "imap_port": 993,
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_mode": "starttls",
        "auth_kind": "oauth2",
        "credential_record": f"microsoft:{alias}",
        "folders": ["INBOX", "Archive"],
        "archive_folder": "Archive",
        "sent_folder": "Sent",
        "trash_folder": "Trash",
        "safe_move_folders": ["Archive"],
        "copy_preserve_source_fallback": False,
        "enabled": True,
    }


def test_private_account_manager_add_disable_enable_and_conflict(tmp_path: Path) -> None:
    path = tmp_path / "private" / "accounts.json"
    manager = AccountConfigManager(path)
    empty = manager.snapshot()
    assert empty["accounts"] == []
    added = manager.add(_account(), expected_revision=empty["revision"])
    assert path.stat().st_mode & 0o077 == 0
    assert added["accounts"][0]["address"] == "mailbox@work.example"
    assert added["accounts"][0]["default_from"] == "public-name@work.example"
    assert load_account_configs(path)[0].alias == "work"

    with pytest.raises(AccountConfigConflict):
        manager.add(_account("other"), expected_revision=empty["revision"])
    with pytest.raises(AccountAdminError, match="malformed or duplicated"):
        manager.add(
            {**_account("other"), "password": "must-never-be-accepted"},
            expected_revision=added["revision"],
        )

    disabled = manager.set_enabled("work", enabled=False, expected_revision=added["revision"])
    assert disabled["accounts"][0]["enabled"] is False
    assert load_account_configs(path) == ()
    assert load_account_configs(path, include_disabled=True)[0].enabled is False
    enabled = manager.set_enabled("work", enabled=True, expected_revision=disabled["revision"])
    assert enabled["removal_semantics"].startswith("disable-only")


def test_account_manager_rejects_symlink_and_unsafe_permissions(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"schema_version": 1, "accounts": []}))
    target.chmod(0o600)
    link = tmp_path / "accounts.json"
    link.symlink_to(target)
    with pytest.raises(AccountAdminError, match="symlink"):
        AccountConfigManager(link).snapshot()
    link.unlink()
    target.rename(link)
    link.chmod(0o644)
    with pytest.raises(AccountAdminError, match="0600"):
        AccountConfigManager(link).snapshot()
    link.unlink()
    link.symlink_to(tmp_path / "missing.json")
    with pytest.raises(AccountAdminError, match="symlink"):
        AccountConfigManager(link).snapshot()


def test_generic_app_password_cli_reads_secret_only_from_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    account = {
        **_account("personal"),
        "auth_kind": "password",
        "credential_record": "password:personal",
    }
    account_path = tmp_path / "accounts.json"
    account_path.write_text(json.dumps({"schema_version": 1, "accounts": [account]}))
    account_path.chmod(0o600)
    key = generate_key()
    key_path = tmp_path / "key"
    key_path.write_text(encode_key(key))
    key_path.chmod(0o600)
    settings = Settings(
        account_config_file=account_path,
        credential_db=tmp_path / "credentials.db",
        credential_key_file=key_path,
    )
    monkeypatch.setattr(credential_admin, "get_settings", lambda: settings)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.TextIOWrapper(io.BytesIO(b"app-password-value\n"), encoding="utf-8"),
    )
    monkeypatch.setattr(
        sys, "argv", ["evergarden-provider-credential", "set-password", "--account", "personal"]
    )
    credential_admin.main()
    result = json.loads(capsys.readouterr().out)
    assert result == {"account": "personal", "credential_version": 1, "stored": True}
    store = CredentialStore(settings.credential_db, key=key, host_id=settings.host_id)
    assert store.get("password:personal")["password"] == "app-password-value"

    monkeypatch.setattr(sys, "argv", ["evergarden-provider-credential", "status"])
    credential_admin.main()
    status = capsys.readouterr().out
    assert "app-password-value" not in status
    assert json.loads(status)["accounts"][0]["credential_present"] is True


def test_encrypted_global_notes_and_mailbox_preferences_are_revision_checked(
    tmp_path: Path,
) -> None:
    store = CredentialStore(tmp_path / "credentials.db", key=generate_key(), host_id="test")
    account_path = tmp_path / "accounts.json"
    account_path.write_text(json.dumps({"schema_version": 1, "accounts": [_account()]}))
    account_path.chmod(0o600)
    preferences = MailPreferenceStore(store, accounts=load_account_configs(account_path))
    initial = preferences.get()
    assert initial["revision"] == 0
    global_value = preferences.edit_global_notes(
        expected_revision=0, notes="Prefer concise replies and preserve receipts."
    )
    updated = preferences.edit_mailbox(
        account="work",
        expected_revision=global_value["revision"],
        description="Work correspondence",
        preferences="Flag deadlines; archive completed threads.",
    )
    assert updated["mailboxes"]["work"]["description"] == "Work correspondence"
    assert b"Prefer concise replies" not in store.path.read_bytes()
    with pytest.raises(MailPreferenceConflict):
        preferences.edit_global_notes(expected_revision=0, notes="stale")
    with pytest.raises(MailPreferenceError, match="secret"):
        preferences.edit_global_notes(
            expected_revision=updated["revision"], notes="password = do-not-store"
        )
    with pytest.raises(MailPreferenceError, match="revision"):
        preferences.edit_global_notes(expected_revision="2", notes="bad")  # type: ignore[arg-type]


def test_staged_attachment_is_encrypted_immutable_bounded_and_consumed(tmp_path: Path) -> None:
    now = dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.UTC)
    credentials = CredentialStore(tmp_path / "credentials.db", key=generate_key(), host_id="test")
    staged = StagedAttachmentStore(credentials, now=lambda: now)
    content = b"safe attachment text"
    result = staged.stage(
        filename="note.txt",
        mimetype="text/plain",
        content_base64=base64.b64encode(content).decode(),
    )
    reference = {
        key: result[key]
        for key in ("staged_attachment_id", "filename", "mimetype", "size", "sha256")
    }
    assert staged.content(reference) == (content, "note.txt", "text/plain")
    assert content not in credentials.path.read_bytes()
    with pytest.raises(StagedAttachmentError, match="changed"):
        staged.content({**reference, "size": 999})
    staged.consume([reference])
    with pytest.raises(StagedAttachmentError, match="expired or consumed"):
        staged.describe(result["staged_attachment_id"])
    with pytest.raises(StagedAttachmentError, match="executable"):
        staged.stage(
            filename="run.txt",
            mimetype="text/plain",
            content_base64=base64.b64encode(b"#!/bin/sh\nexit 0").decode(),
        )


def test_verification_codes_require_recent_context_and_general_reads_redact(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "archive"
    writer = ArchiveWriter(archive)
    writer.upsert(
        message_record(
            "1" * 24,
            subject="Your verification code is 482913",
            body="Use security code 482913 to sign in. It expires soon.",
            received="2026-08-18T11:55:00+00:00",
        )
    )
    writer.upsert(
        message_record(
            "2" * 24,
            uid=2,
            subject="Invoice 20260818",
            body="Total 482913 without authentication context.",
            received="2026-08-18T11:56:00+00:00",
        )
    )
    reader = ArchiveReader(archive)
    value = find_verification_codes(
        reader,
        account="gmail",
        sender_domain="example.test",
        minutes=15,
        limit=5,
        now=dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.UTC),
    )
    assert value["automatic_submission"] is False
    assert [item["codes"] for item in value["matches"]] == [["482913"]]
    assert "482913" not in reader.get_message("1" * 24)["body_text"]
    with pytest.raises(VerificationCodeError, match="domain"):
        find_verification_codes(
            reader,
            account=None,
            sender_domain="not a domain",
            minutes=15,
            limit=5,
        )


class FakeGateway:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    async def ping(self) -> None:
        pass

    async def call(self, name: str, arguments: dict):
        self.calls.append((name, arguments))
        return {"tool": name, "arguments": arguments}


def test_mail_ui_mcp_gateway_reloads_private_token_and_validates_jsonrpc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = _private(tmp_path / "token", "token-" + "x" * 48)
    mode = {"value": "ok"}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {_private_token(token_file)}"
        request_value = json.loads(request.content)
        if mode["value"] == "reject":
            return httpx.Response(403, request=request)
        if mode["value"] == "malformed":
            return httpx.Response(200, content=b"not-json", request=request)
        if mode["value"] == "mismatch":
            return httpx.Response(200, json={"id": "wrong"}, request=request)
        if mode["value"] == "tool-error":
            return httpx.Response(
                200,
                json={"id": request_value["id"], "error": {"message": "bounded error"}},
                request=request,
            )
        if mode["value"] == "oversize":
            return httpx.Response(200, content=b"x" * 32, request=request)
        if mode["value"] == "network":
            raise httpx.ConnectError("simulated connection failure", request=request)
        if mode["value"] == "timeout":
            raise httpx.ReadTimeout("simulated slow tool", request=request)
        if mode["value"] == "execution-error":
            return httpx.Response(
                200,
                json={
                    "id": request_value["id"],
                    "result": {
                        "isError": True,
                        "content": [
                            {
                                "type": "text",
                                "text": "source message content changed after approval",
                            }
                        ],
                    },
                },
                request=request,
            )
        if mode["value"] == "sync-incomplete":
            text = json.dumps(
                {
                    "error": "mail_sync_incomplete",
                    "failed_accounts": [
                        {
                            "account": "personal",
                            "error_class": "gaierror",
                            # Longer than the 300-character bound on tool errors.
                            "error_detail": "[Errno -2] Name or service not known" + " " * 400,
                        }
                    ],
                    "partial_results": [],
                }
            )
            return httpx.Response(
                200,
                json={
                    "id": request_value["id"],
                    "result": {"isError": True, "content": [{"type": "text", "text": text}]},
                },
                request=request,
            )
        if request_value["method"] == "ping":
            return httpx.Response(
                200, json={"id": request_value["id"], "result": {}}, request=request
            )
        return httpx.Response(
            200,
            json={
                "id": request_value["id"],
                "result": {"content": [{"type": "text", "text": '{"ok":true}'}]},
            },
            request=request,
        )

    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        mail_ui_module.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=transport, **kwargs),
    )
    gateway = McpGateway(url="http://mcp:8000/mcp", token_file=token_file)
    asyncio.run(gateway.ping())
    assert asyncio.run(gateway.call("service_info", {})) == {"ok": True}
    for failure in ("reject", "malformed", "mismatch", "tool-error"):
        mode["value"] = failure
        with pytest.raises(RuntimeError):
            asyncio.run(gateway.call("service_info", {}))
        with pytest.raises(RuntimeError):
            asyncio.run(gateway.ping())
    mode["value"] = "execution-error"
    with pytest.raises(McpToolError, match="content changed"):
        asyncio.run(gateway.call("service_info", {}))
    mode["value"] = "sync-incomplete"
    with pytest.raises(McpSyncIncomplete) as incomplete:
        asyncio.run(gateway.call("sync_mail", {}))
    assert incomplete.value.failures == [
        {
            "account": "personal",
            "reason": "dns",
            "error_class": "gaierror",
            "detail": "[Errno -2] Name or service not known",
            "folders": [],
        }
    ]
    mode["value"] = "oversize"
    monkeypatch.setattr(mail_ui_module, "MAX_MCP_RESPONSE_BYTES", 10)
    with pytest.raises(RuntimeError, match="exceeds"):
        asyncio.run(gateway.call("service_info", {}))
    mode["value"] = "network"
    with pytest.raises(McpTransportError, match="temporarily unavailable"):
        asyncio.run(gateway.call("service_info", {}))
    mode["value"] = "timeout"
    with pytest.raises(McpTransportError, match="did not respond in time"):
        asyncio.run(gateway.call("service_info", {}))

    token_file.chmod(0o644)
    with pytest.raises(RuntimeError, match="0600"):
        _private_token(token_file)
    token_file.unlink()
    token_file.symlink_to(tmp_path / "missing")
    with pytest.raises(RuntimeError, match="symlink"):
        _private_token(token_file)


def _private(path: Path, value: str) -> Path:
    path.write_text(value)
    path.chmod(0o600)
    return path


def _admin_files(tmp_path: Path) -> tuple[Path, Path, str]:
    password = "correct horse battery staple"
    credential_file = _private(
        tmp_path / "admin.json",
        json.dumps(credential_document("admin", password)),
    )
    session_key_file = _private(
        tmp_path / "admin-session",
        base64.urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode(),
    )
    return credential_file, session_key_file, password


def _login(client: TestClient, password: str) -> dict:
    response = client.post("/api/login", json={"username": "admin", "password": password})
    assert response.status_code == 200
    assert "Max-Age=604800" in response.headers["set-cookie"]
    return response.json()


class SyncFailingGateway(FakeGateway):
    async def call(self, name: str, arguments: dict):
        self.calls.append((name, arguments))
        raise McpSyncIncomplete(
            [
                {
                    "account": "personal",
                    "reason": "auth",
                    "error_class": "error",
                    "detail": "LOGIN failed.",
                    "folders": [],
                }
            ]
        )


def test_failed_sync_returns_per_mailbox_failures_with_a_reason_code(tmp_path: Path) -> None:
    credential_file, session_key_file, password = _admin_files(tmp_path)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=_private(tmp_path / "token", "mcp-token-" + "y" * 48),
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
    )
    client = TestClient(create_app(settings, gateway=SyncFailingGateway()))
    _login(client, password)
    session = client.get("/api/session").json()
    response = client.post(
        "/api/mcp/sync_mail",
        json={"arguments": {}},
        headers={"X-CSRF-Token": session["csrf"]},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["reason_code"] == "MAIL_SYNC_INCOMPLETE"
    assert body["detail"] == "MAIL_SYNC_INCOMPLETE: 1 mailbox(es) did not sync"
    assert body["sync_failures"][0]["account"] == "personal"
    assert body["sync_failures"][0]["reason"] == "auth"


def test_login_throttle_keys_on_the_gateway_address_not_a_client_supplied_chain(
    tmp_path: Path,
) -> None:
    credential_file, session_key_file, _password = _admin_files(tmp_path)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=_private(tmp_path / "token", "mcp-token-" + "y" * 48),
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
        admin_login_max_failures=3,
    )
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    wrong = {"username": "admin", "password": "wrong"}
    gateway_view = {"X-Forwarded-For": "198.51.100.7"}
    statuses = [client.post("/api/login", json=wrong, headers=gateway_view).status_code]
    statuses += [client.post("/api/login", json=wrong, headers=gateway_view).status_code]
    statuses += [client.post("/api/login", json=wrong, headers=gateway_view).status_code]
    assert statuses == [401, 401, 401]
    assert client.post("/api/login", json=wrong, headers=gateway_view).status_code == 429
    # A client that prepends its own entries to the chain must not get a fresh bucket.
    for spoofed in ("203.0.113.1", "203.0.113.2, 192.0.2.9"):
        response = client.post(
            "/api/login",
            json=wrong,
            headers={"X-Forwarded-For": f"{spoofed}, 198.51.100.7"},
        )
        assert response.status_code == 429


def test_login_throttle_keys_ipv6_clients_by_their_64(tmp_path: Path) -> None:
    from apps.mail_ui.main import throttle_key

    assert throttle_key("2001:db8::1") == "2001:db8::/64"
    assert throttle_key("2001:DB8::A") == "2001:db8::/64"
    assert throttle_key("2001:db8:0:1::1") == "2001:db8:0:1::/64"
    assert throttle_key("::ffff:198.51.100.7") == "198.51.100.7"
    assert throttle_key("198.51.100.7") == "198.51.100.7"
    assert throttle_key("not-an-address") is None

    credential_file, session_key_file, _password = _admin_files(tmp_path)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=_private(tmp_path / "token", "mcp-token-" + "y" * 48),
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
        admin_login_max_failures=3,
    )
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    wrong = {"username": "admin", "password": "wrong"}
    statuses = [
        client.post(
            "/api/login", json=wrong, headers={"X-Forwarded-For": f"2001:db8::{suffix}"}
        ).status_code
        for suffix in ("1", "2", "3", "4", "ffff:1")
    ]
    # Rotating addresses inside one /64 does not earn fresh guesses.
    assert statuses == [401, 401, 401, 429, 429]
    other = client.post("/api/login", json=wrong, headers={"X-Forwarded-For": "2001:db8:1::1"})
    assert other.status_code == 401


def test_mail_ui_uses_local_admin_login_csrf_and_ignores_forged_proxy_identity(
    tmp_path: Path,
) -> None:
    credential_file, session_key_file, password = _admin_files(tmp_path)
    token_file = _private(tmp_path / "token", "mcp-token-" + "y" * 48)
    account_file = tmp_path / "accounts.json"
    gateway = FakeGateway()
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_account_admin_enabled=True,
        mail_ui_mcp_token_file=token_file,
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        account_config_file=account_file,
        admin_secure_cookies=False,
        admin_session_revocation_file=tmp_path / "mail-config" / "revocations.json",
    )
    client = TestClient(
        create_app(
            settings,
            gateway=gateway,
            account_manager=AccountConfigManager(account_file),
        )
    )
    assert client.get("/healthz").json() == {
        "ok": True,
        "enabled": True,
        "account_admin_enabled": True,
        "authentication": "local-password",
    }
    redirect = client.get("/", follow_redirects=False)
    assert redirect.status_code == 303
    assert redirect.headers["location"] == "/login"
    assert client.get("/api/session").status_code == 401
    assert (
        client.get(
            "/api/session",
            headers={
                "X-Evergarden-Proxy-Secret": "forged",
                "Remote-User": "admin",
                "Remote-Groups": "evergarden-admins",
            },
        ).status_code
        == 401
    )
    assert client.get("/login").status_code == 200
    assert client.get("/assets/login.js").status_code == 200
    assert (
        client.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code
        == 401
    )
    _login(client, password)
    page = client.get("/")
    assert page.status_code == 200
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/not-allowed").status_code == 404
    session = client.get("/api/session").json()
    assert session["subject"] == "admin"
    # The MCP setup guide needs public discovery values, never the UI's own bearer.
    assert session["mcp_resource"] == str(settings.mcp_resource)
    assert (
        session["mcp_discovery_url"]
        == "https://evergarden.example.invalid/.well-known/oauth-protected-resource/mcp"
    )
    # No JWKS or introspection here, so the issuer is not trusted or advertised.
    assert session["mcp_oauth_enabled"] is False
    assert session["oauth_issuer"] is None
    assert "mail:read" in session["mcp_scopes"]
    assert token_file.read_text(encoding="utf-8") not in json.dumps(session)
    assert client.post("/api/mcp/list_accounts", json={"arguments": {}}).status_code == 403
    called = client.post(
        "/api/mcp/list_accounts",
        json={"arguments": {}},
        headers={"X-CSRF-Token": session["csrf"]},
    )
    assert called.json()["tool"] == "list_accounts"
    assert gateway.calls == [("list_accounts", {})]
    assert (
        client.post(
            "/api/mcp/not_a_tool",
            json={"arguments": {}},
            headers={"X-CSRF-Token": session["csrf"]},
        ).status_code
        == 404
    )
    empty = client.get("/api/admin/accounts").json()
    added = client.post(
        "/api/admin/accounts",
        json={"expected_revision": empty["revision"], "account": _account()},
        headers={"X-CSRF-Token": session["csrf"]},
    )
    assert added.status_code == 200
    assert added.json()["accounts"][0]["alias"] == "work"
    assert load_account_configs(account_file)[0].address == "mailbox@work.example"
    stale = client.post(
        "/api/admin/accounts",
        json={"expected_revision": empty["revision"], "account": _account("other")},
        headers={"X-CSRF-Token": session["csrf"]},
    )
    assert stale.status_code == 409
    disabled = client.post(
        "/api/admin/accounts/work/state",
        json={"expected_revision": added.json()["revision"], "enabled": False},
        headers={"X-CSRF-Token": session["csrf"]},
    )
    assert disabled.status_code == 200
    assert disabled.json()["accounts"][0]["enabled"] is False
    assert client.post("/api/logout", headers={"X-CSRF-Token": session["csrf"]}).status_code == 200
    assert client.get("/api/session").status_code == 401


def test_api_key_endpoints_are_fenced_off_until_explicitly_enabled(tmp_path: Path) -> None:
    credential_file, session_key_file, password = _admin_files(tmp_path)
    token_file = _private(tmp_path / "token", "mcp-token-" + "y" * 48)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=token_file,
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
    )
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    _login(client, password)
    session = client.get("/api/session").json()
    assert session["api_keys_enabled"] is False
    assert client.get("/api/admin/api-keys").status_code == 503
    assert (
        client.post(
            "/api/admin/api-keys",
            json={
                "expected_revision": "0" * 64,
                "label": "laptop",
                "scopes": ["mail:read"],
                "ttl_days": 30,
            },
            headers={"X-CSRF-Token": session["csrf"]},
        ).status_code
        == 503
    )


def test_api_keys_are_issued_listed_and_revoked_without_leaking_plaintext(
    tmp_path: Path,
) -> None:
    credential_file, session_key_file, password = _admin_files(tmp_path)
    token_file = _private(tmp_path / "token", "mcp-token-" + "y" * 48)
    registry = tmp_path / "api-keys" / "api_keys.json"
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_api_keys_enabled=True,
        mcp_api_keys_file=registry,
        mail_ui_mcp_token_file=token_file,
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
    )
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    assert client.get("/api/admin/api-keys").status_code == 401
    _login(client, password)
    session = client.get("/api/session").json()
    assert session["api_keys_enabled"] is True

    empty = client.get("/api/admin/api-keys").json()
    assert empty["keys"] == []

    body = {
        "expected_revision": empty["revision"],
        "label": "Laptop",
        "scopes": ["mail:read", "mail:metadata"],
        "ttl_days": 90,
    }
    assert client.post("/api/admin/api-keys", json=body).status_code == 403
    created = client.post(
        "/api/admin/api-keys", json=body, headers={"X-CSRF-Token": session["csrf"]}
    )
    assert created.status_code == 200
    issued = created.json()
    assert issued["client_id"] == "ui-laptop"
    assert len(issued["token"]) >= 43

    # A second write against the consumed revision must not silently succeed.
    assert (
        client.post(
            "/api/admin/api-keys", json=body, headers={"X-CSRF-Token": session["csrf"]}
        ).status_code
        == 409
    )

    listed = client.get("/api/admin/api-keys")
    assert listed.status_code == 200
    assert issued["token"] not in listed.text
    assert [key["client_id"] for key in listed.json()["keys"]] == ["ui-laptop"]

    # The registry the MCP service reads carries a hash, never the plaintext.
    assert issued["token"] not in registry.read_text(encoding="utf-8")
    assert hashlib.sha256(issued["token"].encode()).hexdigest() in registry.read_text(
        encoding="utf-8"
    )

    revoked = client.post(
        f"/api/admin/api-keys/{issued['client_id']}/revoke",
        json={"expected_revision": listed.json()["revision"]},
        headers={"X-CSRF-Token": session["csrf"]},
    )
    assert revoked.status_code == 200
    assert revoked.json()["keys"] == []
    assert (
        client.post(
            f"/api/admin/api-keys/{issued['client_id']}/revoke",
            json={"expected_revision": revoked.json()["revision"]},
            headers={"X-CSRF-Token": session["csrf"]},
        ).status_code
        == 400
    )


def test_mail_ui_disabled_and_gateway_failures_remain_closed(tmp_path: Path) -> None:
    disabled = TestClient(create_app(Settings()))
    assert disabled.get("/healthz").json()["enabled"] is False
    assert disabled.get("/").status_code == 503

    class FailingGateway:
        async def ping(self):
            raise McpTransportError("MCP authentication expired")

        async def call(self, _name: str, _arguments: dict):
            raise RuntimeError("upstream rejected")

    credential_file, session_key_file, password = _admin_files(tmp_path)
    token_file = _private(tmp_path / "token", "mcp-token-" + "y" * 48)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=token_file,
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
    )
    client = TestClient(create_app(settings, gateway=FailingGateway()))
    assert client.get("/healthz").status_code == 503
    _login(client, password)
    csrf = client.get("/api/session").json()["csrf"]
    failed = client.post(
        "/api/mcp/service_info",
        json={"arguments": {}},
        headers={"X-CSRF-Token": csrf},
    )
    assert failed.status_code == 400
    assert failed.json()["detail"] == "upstream rejected"
    assert (
        client.post(
            "/api/mcp/service_info",
            json={"arguments": {}},
            headers={"X-CSRF-Token": csrf, "Content-Length": "invalid"},
        ).status_code
        == 400
    )

    class UnavailableGateway:
        async def call(self, _name: str, _arguments: dict):
            raise McpTransportError("MCP is temporarily unavailable")

    unavailable = TestClient(create_app(settings, gateway=UnavailableGateway()))
    _login(unavailable, password)
    unavailable_csrf = unavailable.get("/api/session").json()["csrf"]
    response = unavailable.post(
        "/api/mcp/service_info",
        json={"arguments": {}},
        headers={"X-CSRF-Token": unavailable_csrf},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "MCP is temporarily unavailable"

    class UnexpectedFailureGateway:
        async def call(self, _name: str, _arguments: dict):
            raise ValueError("private upstream content must not leak")

    unexpected = TestClient(create_app(settings, gateway=UnexpectedFailureGateway()))
    _login(unexpected, password)
    response = unexpected.post(
        "/api/mcp/service_info",
        json={"arguments": {}},
        headers={"X-CSRF-Token": unexpected.get("/api/session").json()["csrf"]},
    )
    assert response.status_code == 500
    assert response.headers["content-type"] == "application/json"
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert len(response.headers["x-request-id"]) == 32
    assert response.headers["cache-control"] == "no-store"
    assert "private upstream content" not in response.text


def test_mail_ui_mcp_gateway_selects_timeout_per_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = _private(tmp_path / "token", "token-" + "x" * 48)
    timeouts: list[float | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        value = json.loads(request.content)
        result = {} if value["method"] == "ping" else {"content": [{"type": "text", "text": "{}"}]}
        return httpx.Response(200, json={"id": value["id"], "result": result}, request=request)

    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def recording_client(**kwargs):
        timeouts.append(kwargs["timeout"].read)
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(mail_ui_module.httpx, "AsyncClient", recording_client)
    gateway = McpGateway(url="http://mcp:8000/mcp", token_file=token_file)
    expected = {
        "trash_approved": 150.0,
        "send_approved": 150.0,
        "move_unrelated_approved": 150.0,
        "sync_mail": 150.0,
        "prepare_send": 60.0,
        "preview_trash": 60.0,
        "preview_move_unrelated": 60.0,
        "list_accounts": 15.0,
        "get_draft_status": 15.0,
    }
    for name, timeout in expected.items():
        assert mail_ui_module.mcp_call_timeout(name) == timeout
        assert asyncio.run(gateway.call(name, {})) == {}
    asyncio.run(gateway.ping())
    assert timeouts == [*expected.values(), 15.0]


def test_mail_ui_token_file_failure_is_a_transport_error_without_file_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(**_kwargs):
        pytest.fail("MCP must not be contacted without a valid private token")

    monkeypatch.setattr(mail_ui_module.httpx, "AsyncClient", no_network)
    missing = McpGateway(url="http://mcp:8000/mcp", token_file=tmp_path / "missing-token")
    with pytest.raises(McpTransportError, match="credential is unavailable"):
        asyncio.run(missing.call("list_accounts", {}))
    with pytest.raises(McpTransportError, match="credential is unavailable"):
        asyncio.run(missing.ping())
    unsafe = _private(tmp_path / "unsafe-token", "token-" + "x" * 48)
    unsafe.chmod(0o644)
    with pytest.raises(McpTransportError, match="credential is unavailable"):
        asyncio.run(McpGateway(url="http://mcp:8000/mcp", token_file=unsafe).call("sync_mail", {}))

    credential_file, session_key_file, password = _admin_files(tmp_path)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=tmp_path / "missing-token",
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
    )
    client = TestClient(create_app(settings, gateway=missing))
    _login(client, password)
    response = client.post(
        "/api/mcp/list_accounts",
        json={"arguments": {}},
        headers={"X-CSRF-Token": client.get("/api/session").json()["csrf"]},
    )
    assert response.status_code == 503
    assert response.headers["content-type"] == "application/json"
    assert response.json()["detail"] == "mail UI internal MCP credential is unavailable"
    assert "missing-token" not in response.text
    assert str(tmp_path) not in response.text


def test_mail_ui_bridge_unexpected_failure_returns_json_500(tmp_path: Path) -> None:
    credential_file, session_key_file, password = _admin_files(tmp_path)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=tmp_path / "token",
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
        thunderbird_bridge_accounts="work",
        thunderbird_bridge_clients_file=tmp_path / "clients.json",
        archive_dir=tmp_path / "archive",
        # The bridge mailbox cannot open its archive key, which is not a mapped error.
        credential_key_file=tmp_path / "missing-credential-key",
    )
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    _login(client, password)
    response = client.get("/bridge/status")
    assert response.status_code == 500
    assert response.headers["content-type"] == "application/json"
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert len(response.headers["x-request-id"]) == 32
    assert response.headers["cache-control"] == "no-store"
    assert "credential key" not in response.text
    assert "missing-credential-key" not in response.text


def test_mail_ui_serves_shared_json_helper_without_session(tmp_path: Path) -> None:
    credential_file, session_key_file, _password = _admin_files(tmp_path)
    settings = Settings(
        mail_ui_enabled=True,
        mail_ui_mcp_token_file=tmp_path / "token",
        admin_credential_file=credential_file,
        admin_session_key_file=session_key_file,
        admin_secure_cookies=False,
    )
    client = TestClient(create_app(settings, gateway=FakeGateway()))
    shared = Path("apps/shared_static/http.js").resolve()
    assert mail_ui_module.SHARED_ASSET_DIR / "http.js" == shared
    assert client.get("/api/session").status_code == 401
    response = client.get("/assets/http.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert response.content == shared.read_bytes()
    # Page scripts stay behind the administrator session.
    assert client.get("/assets/app.js").status_code == 401
