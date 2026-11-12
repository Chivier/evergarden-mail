from __future__ import annotations

import base64
import copy
import datetime as dt
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from evergarden.auth.admin_session import (
    AdminAuthError,
    AdminSessionAuth,
    LoginThrottle,
    credential_document,
    read_admin_credential,
    read_session_key,
)
from evergarden.auth.credential_store import CredentialStore, CredentialStoreError, generate_key
from evergarden.config import Settings
from evergarden.mail.account_admin import AccountAdminError, AccountConfigManager
from evergarden.mail.models import (
    AccountConfigError,
    account_config_payload,
    load_account_configs,
    parse_account_config_payload,
)
from evergarden.mail.preferences import MailPreferenceError, MailPreferenceStore
from evergarden.mail.staged_attachments import (
    RECORD_PREFIX,
    StagedAttachmentError,
    StagedAttachmentStore,
)


def _account(alias: str = "work") -> dict:
    return {
        "alias": alias,
        "address": f"mailbox@{alias}.example",
        "imap_host": "imap.example.test",
        "imap_port": 993,
        "smtp_host": "smtp.example.test",
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


def _payload(account: dict | None = None) -> dict:
    return {"schema_version": 1, "accounts": [account or _account()]}


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"unexpected": True}, "unexpected fields"),
        ({"alias": "Bad Alias"}, "lowercase token"),
        ({"address": "not-an-address"}, "address is malformed"),
        ({"imap_host": "bad host"}, "provider host"),
        ({"smtp_host": "bad host"}, "provider host"),
        ({"auth_kind": "basic"}, "auth_kind"),
        ({"credential_record": "bad record"}, "credential_record"),
        ({"folders": []}, "folders must contain"),
        ({"folders": ["INBOX", "inbox"]}, "duplicate folders"),
        ({"safe_move_folders": ["Trash"]}, "allowlisted"),
        ({"safe_move_folders": ["Archive", "Spam"]}, "destructive or junk"),
        ({"trash_folder": "Archive"}, "must be separate"),
        ({"copy_preserve_source_fallback": "yes"}, "must be boolean"),
        ({"send_from_addresses": []}, "must contain 1-16"),
        ({"send_from_addresses": ["not-an-address"]}, "malformed address"),
        (
            {"send_from_addresses": ["mailbox@work.example", "MAILBOX@work.example"]},
            "duplicate addresses",
        ),
        ({"send_from_addresses": ["public@work.example"]}, "authentication address"),
        ({"enabled": 1}, "must be boolean"),
        ({"smtp_mode": "plain"}, "smtp_mode"),
        ({"imap_port": 0}, "TCP port"),
        ({"smtp_port": True}, "TCP port"),
    ],
)
def test_account_inventory_rejects_unsafe_fields(update: dict, message: str) -> None:
    account = _account()
    account.update(update)
    with pytest.raises(AccountConfigError, match=message):
        parse_account_config_payload(_payload(account), include_disabled=True)


def test_account_inventory_root_uniqueness_and_private_file_checks(tmp_path: Path) -> None:
    with pytest.raises(AccountConfigError, match="root"):
        parse_account_config_payload([])
    with pytest.raises(AccountConfigError, match="schema version"):
        parse_account_config_payload({"schema_version": 2, "accounts": []})
    with pytest.raises(AccountConfigError, match="0-16"):
        parse_account_config_payload({"schema_version": 1, "accounts": [_account()] * 17})
    with pytest.raises(AccountConfigError, match="each account"):
        parse_account_config_payload({"schema_version": 1, "accounts": ["bad"]})
    missing = _account()
    missing.pop("trash_folder")
    with pytest.raises(AccountConfigError, match="missing fields"):
        parse_account_config_payload(_payload(missing))

    for field, replacement in (
        ("alias", "work"),
        ("address", "mailbox@work.example"),
        ("credential_record", "microsoft:work"),
    ):
        first = _account()
        second = _account("other")
        second[field] = replacement
        with pytest.raises(AccountConfigError, match="duplicate"):
            parse_account_config_payload(
                {"schema_version": 1, "accounts": [first, second]},
                include_disabled=True,
            )

    first = _account()
    first["send_from_addresses"] = [first["address"], "shared@example.test"]
    second = _account("other")
    second["send_from_addresses"] = [second["address"], "shared@example.test"]
    with pytest.raises(AccountConfigError, match="duplicate send-from"):
        parse_account_config_payload(
            {"schema_version": 1, "accounts": [first, second]}, include_disabled=True
        )

    missing_path = tmp_path / "missing.json"
    with pytest.raises(AccountConfigError, match="missing"):
        load_account_configs(missing_path)
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(AccountConfigError, match="regular mode-0600"):
        load_account_configs(directory)
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{")
    malformed.chmod(0o600)
    with pytest.raises(AccountConfigError, match="valid JSON"):
        load_account_configs(malformed)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (128 * 1024 + 1))
    oversized.chmod(0o600)
    with pytest.raises(AccountConfigError, match="128 KiB"):
        load_account_configs(oversized)


def test_visible_from_allowlist_defaults_safely_and_preserves_order() -> None:
    legacy = parse_account_config_payload(_payload())[0]
    assert legacy.allowed_from_addresses == ("mailbox@work.example",)
    assert legacy.default_from_address == "mailbox@work.example"

    account = _account()
    account["send_from_addresses"] = ["public-name@work.example", account["address"]]
    parsed = parse_account_config_payload(_payload(account))[0]
    assert parsed.allowed_from_addresses == (
        "public-name@work.example",
        "mailbox@work.example",
    )
    assert parsed.default_from_address == "public-name@work.example"
    assert account_config_payload((parsed,))["accounts"][0]["send_from_addresses"] == [
        "public-name@work.example",
        "mailbox@work.example",
    ]


def test_account_manager_rejects_malformed_state_requests(tmp_path: Path) -> None:
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps(_payload()))
    path.chmod(0o600)
    manager = AccountConfigManager(path)
    revision = manager.snapshot()["revision"]
    with pytest.raises(AccountAdminError, match="malformed"):
        manager.set_enabled("work", enabled=1, expected_revision=revision)  # type: ignore[arg-type]
    with pytest.raises(AccountAdminError, match="unknown"):
        manager.set_enabled("missing", enabled=False, expected_revision=revision)
    path.write_text("{")
    with pytest.raises(AccountAdminError, match="malformed"):
        manager.snapshot()

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(AccountAdminError, match=r"directory.*symlink"):
        AccountConfigManager(linked_parent / "accounts.json").snapshot()

    lock_target = tmp_path / "lock-target"
    lock_target.write_text("keep", encoding="utf-8")
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.unlink()
    lock_path.symlink_to(lock_target)
    with pytest.raises(AccountAdminError, match="lock file is unsafe"):
        AccountConfigManager(path).snapshot()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mcp_resource": "http://mail.example.test/mcp"},
        {"oauth_introspection_url": "https://auth.example.test/introspect"},
        {"microsoft_oauth_client_id": "bad client"},
        {"microsoft_oauth_tenant": "bad/tenant"},
        {"microsoft_oauth_redirect_uri": "http://remote.example.test/callback"},
        {"mail_ui_mcp_url": "http://remote.example.test/mcp"},
        {"mail_ui_mcp_url": "http://mcp:8000/not-mcp"},
        {"mail_ui_approval_url": "http://remote.example.test"},
        {"admin_session_ttl_seconds": 299},
        {"admin_session_ttl_seconds": 2592001},
        {"admin_login_max_failures": 2},
        {"admin_login_window_seconds": 59},
        {"mail_ui_enabled": True},
        {"mail_ui_account_admin_enabled": True},
        {"approval_ui_enabled": True},
    ],
)
def test_runtime_settings_reject_incomplete_or_remote_cleartext_surfaces(kwargs: dict) -> None:
    with pytest.raises(ValidationError):
        Settings(**kwargs)


def test_local_admin_password_session_and_private_files_are_strict(tmp_path: Path) -> None:
    credential_path = tmp_path / "admin.json"
    credential_path.write_text(
        json.dumps(credential_document("admin", "correct horse battery staple"))
    )
    credential_path.chmod(0o600)
    key_path = tmp_path / "session-key"
    key_path.write_text(base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=").decode())
    key_path.chmod(0o600)

    now = [1_800_000_000.0]
    auth = AdminSessionAuth(
        session_key_file=key_path,
        credential_file=credential_path,
        ttl_seconds=300,
        clock=lambda: now[0],
    )
    with pytest.raises(AdminAuthError, match="invalid"):
        auth.verify_login("admin", "incorrect password")
    subject = auth.verify_login("admin", "correct horse battery staple")
    token, issued = auth.issue(subject)
    assert auth.authenticate(token) == issued
    payload, signature = token.split(".", 1)
    tampered = f"{payload}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
    with pytest.raises(AdminAuthError, match="required"):
        auth.authenticate(tampered)
    now[0] += 301
    with pytest.raises(AdminAuthError, match="expired"):
        auth.authenticate(token)

    assert read_admin_credential(credential_path).username == "admin"
    assert read_session_key(key_path) == b"k" * 32
    key_path.chmod(0o644)
    with pytest.raises(AdminAuthError, match="0600"):
        read_session_key(key_path)
    key_path.chmod(0o600)
    credential_path.unlink()
    target = tmp_path / "real-admin.json"
    target.write_text(json.dumps(credential_document("admin", "another strong password")))
    target.chmod(0o600)
    credential_path.symlink_to(target)
    with pytest.raises(AdminAuthError, match="symlink"):
        read_admin_credential(credential_path)


def test_admin_login_throttle_expires_and_resets() -> None:
    now = [1000.0]
    throttle = LoginThrottle(max_failures=3, window_seconds=60, clock=lambda: now[0])
    assert throttle.retry_after("client") == 0
    for _index in range(3):
        throttle.failure("client")
    assert throttle.retry_after("client") == 60
    now[0] += 61
    assert throttle.retry_after("client") == 0
    throttle.failure("client")
    throttle.success("client")
    assert throttle.retry_after("client") == 0


def test_admin_login_throttle_memory_stays_bounded() -> None:
    now = [1000.0]
    throttle = LoginThrottle(max_failures=3, window_seconds=60, clock=lambda: now[0])
    # Checking keys that never failed stores nothing.
    for index in range(1000):
        assert throttle.retry_after(f"probe-{index}") == 0
    assert len(throttle._attempts) == 0
    # Expired failures are dropped instead of leaving empty entries behind.
    throttle.failure("client")
    now[0] += 61
    assert throttle.retry_after("client") == 0
    assert len(throttle._attempts) == 0
    # Distinct failing keys are capped; the oldest is evicted first.
    for index in range(LoginThrottle.MAX_KEYS + 10):
        throttle.failure(f"rotating-{index}")
    assert len(throttle._attempts) == LoginThrottle.MAX_KEYS
    assert "rotating-0" not in throttle._attempts
    for _index in range(3):
        throttle.failure("client")
    assert throttle.retry_after("client") == 60


def test_default_admin_session_is_valid_for_seven_days(tmp_path: Path) -> None:
    key_path = tmp_path / "session-key"
    key_path.write_text(base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=").decode())
    key_path.chmod(0o600)
    now = [1_800_000_000.0]
    auth = AdminSessionAuth(session_key_file=key_path, clock=lambda: now[0])
    assert auth.ttl_seconds == Settings().admin_session_ttl_seconds == 604800
    token, session = auth.issue("admin")
    issued_at = now[0]
    for elapsed in (8 * 60 * 60, 6 * 24 * 60 * 60, 604799):
        now[0] = issued_at + elapsed
        assert auth.authenticate(token) == session
    verifier = AdminSessionAuth(session_key_file=key_path, clock=lambda: now[0])
    assert verifier.authenticate(token) == session
    with pytest.raises(AdminAuthError, match="between 5 minutes and 30 days"):
        AdminSessionAuth(session_key_file=key_path, ttl_seconds=2592001)
    now[0] += 1
    with pytest.raises(AdminAuthError, match="expired"):
        auth.authenticate(token)
    with pytest.raises(AdminAuthError, match="expired"):
        verifier.authenticate(token)


def test_explicit_thirty_day_admin_session_stays_valid(tmp_path: Path) -> None:
    key_path = tmp_path / "session-key"
    key_path.write_text(base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=").decode())
    key_path.chmod(0o600)
    now = [1_800_000_000.0]
    assert Settings(admin_session_ttl_seconds=2592000).admin_session_ttl_seconds == 2592000
    auth = AdminSessionAuth(session_key_file=key_path, ttl_seconds=2592000, clock=lambda: now[0])
    token, session = auth.issue("admin")
    issued_at = now[0]
    for elapsed in (8 * 60 * 60, 7 * 24 * 60 * 60, 2591999):
        now[0] = issued_at + elapsed
        assert auth.authenticate(token) == session
    now[0] += 1
    with pytest.raises(AdminAuthError, match="expired"):
        auth.authenticate(token)


def test_mail_proxy_has_no_authelia_or_forwarded_identity_dependency() -> None:
    npm = Path("deploy/nginx/npm-mail-host-advanced.conf.example").read_text()
    gateway = Path("deploy/nginx/evergarden-gateway.conf").read_text()
    compose = Path("docker-compose.yaml").read_text()
    assert "proxy_pass http://authelia" not in npm
    assert not re.search(r"^\s*auth_request\s", npm, flags=re.MULTILINE)
    assert 'proxy_set_header Remote-User "";' in npm
    assert "proxy_set_header Remote-User $http_remote_user" not in gateway
    assert 'proxy_set_header Remote-User "";' in gateway
    assert "reverse_proxy_secret" not in compose
    assert "admin_credentials.json" in compose
    assert "admin_session_key" in compose


def test_preference_document_validation_and_unknown_mailbox(tmp_path: Path) -> None:
    store = CredentialStore(tmp_path / "credentials.db", key=generate_key(), host_id="test")
    accounts = parse_account_config_payload(_payload())
    preferences = MailPreferenceStore(store, accounts=accounts)
    with pytest.raises(MailPreferenceError, match="unknown or disabled"):
        preferences.edit_mailbox(
            account="missing",
            expected_revision=0,
            description="",
            preferences="",
        )

    invalid_documents = [
        {},
        {"schema_version": 2, "global_notes": "", "mailboxes": {}},
        {"schema_version": 1, "global_notes": "", "mailboxes": []},
        {
            "schema_version": 1,
            "global_notes": "",
            "mailboxes": {
                "Bad Alias": {"description": "", "preferences": ""},
            },
        },
        {
            "schema_version": 1,
            "global_notes": "",
            "mailboxes": {"work": {"description": "missing preferences"}},
        },
    ]
    for index, document in enumerate(invalid_documents):
        record = f"settings:mail-preferences-{index}"
        store.put(record, document)
        value, _version = store.get_with_version(record)
        with pytest.raises(MailPreferenceError):
            MailPreferenceStore._validate_document(value)

    too_many = {
        "schema_version": 1,
        "global_notes": "",
        "mailboxes": {
            f"mailbox-{index}": {"description": "", "preferences": ""} for index in range(65)
        },
    }
    with pytest.raises(MailPreferenceError, match="too many"):
        MailPreferenceStore._validate_document(too_many)
    with pytest.raises(MailPreferenceError, match="malformed"):
        preferences.edit_global_notes(expected_revision=0, notes="bad\0note")


def test_preference_compare_and_swap_failure_remains_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = CredentialStore(tmp_path / "credentials.db", key=generate_key(), host_id="test")
    preferences = MailPreferenceStore(store, accounts=())

    def fail(*_args, **_kwargs):
        raise CredentialStoreError("simulated conflict")

    monkeypatch.setattr(store, "create_if_absent", fail)
    with pytest.raises(Exception, match="changed; reload"):
        preferences.edit_global_notes(expected_revision=0, notes="safe note")


def test_staged_attachment_invalid_expired_limit_and_integrity_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.UTC)
    store = CredentialStore(tmp_path / "credentials.db", key=generate_key(), host_id="test")
    staged = StagedAttachmentStore(store, now=lambda: current)
    with pytest.raises(StagedAttachmentError, match="valid base64"):
        staged.stage(filename="a.txt", mimetype="text/plain", content_base64="***")
    with pytest.raises(StagedAttachmentError, match="id is malformed"):
        staged.describe("bad")
    with pytest.raises(StagedAttachmentError, match="not found"):
        staged.describe("00000000-0000-4000-8000-000000000000")

    first = staged.stage(
        filename="one.txt",
        mimetype="text/plain",
        content_base64=base64.b64encode(b"first").decode(),
    )
    monkeypatch.setattr("evergarden.mail.staged_attachments.MAX_ACTIVE_STAGED_ATTACHMENTS", 1)
    with pytest.raises(StagedAttachmentError, match="too many"):
        staged.stage(
            filename="two.txt",
            mimetype="text/plain",
            content_base64=base64.b64encode(b"second").decode(),
        )

    record_id = RECORD_PREFIX + first["staged_attachment_id"]
    value, version = store.get_with_version(record_id)
    corrupted = copy.deepcopy(value)
    corrupted["content_base64"] = base64.b64encode(b"other").decode()
    store.put_if_version(record_id, expected_version=version, value=corrupted)
    reference = {
        key: first[key]
        for key in ("staged_attachment_id", "filename", "mimetype", "size", "sha256")
    }
    with pytest.raises(StagedAttachmentError, match="integrity"):
        staged.content(reference)

    expired_id = "00000000-0000-4000-8000-000000000001"
    store.put(
        RECORD_PREFIX + expired_id,
        {
            "schema_version": 1,
            "filename": "old.txt",
            "mimetype": "text/plain",
            "size": 3,
            "sha256": "0" * 64,
            "content_base64": base64.b64encode(b"old").decode(),
            "created_at": "2026-08-17T10:00:00+00:00",
            "expires_at": "2026-08-17T11:00:00+00:00",
            "consumed": False,
        },
    )
    with pytest.raises(StagedAttachmentError, match="expired or consumed"):
        staged.describe(expired_id)
    staged.consume([{}, {"staged_attachment_id": "00000000-0000-4000-8000-000000000002"}])
