from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path

import pytest

from evergarden.auth.credential_store import CredentialStore, generate_key
from evergarden.auth.mfa_autologin import (
    AutoLoginError,
    AutoLoginRejected,
    MicrosoftAutoLogin,
    normalize_totp_secret,
    record_id,
    totp,
)
from evergarden.auth.provider_oauth import MICROSOFT_CLIENT_ID_PLACEHOLDER
from evergarden.mail.models import AccountConfig, account_config_payload

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


class FakeClient:
    uses_device_authorization = True
    record_id = "microsoft:work"

    def __init__(self, store: CredentialStore, now):
        self.store = store
        self.now = now
        self.polls: list[str] = []
        self.result = "authorized"

    def start_device_authorization(self) -> dict:
        return {
            "device_code": "device-secret",
            "user_code": "ABCD1234",
            "verification_uri": "https://microsoft.com/devicelogin",
            "interval": 5,
            "expires_at": (self.now() + dt.timedelta(minutes=15)).isoformat(),
        }

    def poll_device_authorization(self, device_code: str) -> str:
        self.polls.append(device_code)
        if self.result == "authorized":
            self.store.put(self.record_id, {"refresh_token": "new", "access_token": "a"})
        return self.result


class Clock:
    def __init__(self, start: float):
        self.value = start

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


def _setup(tmp_path: Path, *, browser=None):
    store = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="host-a"
    )
    clock = Clock(1_800_000_010.0)

    def now() -> dt.datetime:
        return dt.datetime.fromtimestamp(clock(), dt.UTC)

    client = FakeClient(store, now)
    calls: list[dict] = []

    def default_browser(*, verification_uri, user_code, credentials):
        calls.append(
            {
                "uri": verification_uri,
                "code": user_code,
                "username": credentials.username,
                "totp": credentials.next_totp(),
            }
        )

    autologin = MicrosoftAutoLogin(
        store=store,
        clients={"work": client},
        browser_login=browser or default_browser,
        now=now,
        clock=clock,
        sleep=clock.sleep,
    )
    return autologin, store, client, calls, clock


def test_totp_matches_rfc6238_and_rejects_malformed_seeds() -> None:
    # RFC 6238 appendix B, SHA-1, T=59s, truncated to six digits.
    assert totp(RFC_SECRET, 59 // 30, digits=8) == "94287082"
    assert totp(RFC_SECRET, 59 // 30) == "287082"
    assert normalize_totp_secret("gezd gnbv gy3t qojq") == "GEZDGNBVGY3TQOJQ"
    uri = "otpauth://totp/Microsoft:u%40work.example?secret=gezdgnbvgy3tqojq&issuer=Microsoft"
    assert normalize_totp_secret(uri) == "GEZDGNBVGY3TQOJQ"
    with pytest.raises(ValueError):
        normalize_totp_secret(uri + "&digits=8")
    with pytest.raises(ValueError):
        normalize_totp_secret("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1")
    with pytest.raises(ValueError):
        normalize_totp_secret("not base32 !")
    with pytest.raises(ValueError):
        normalize_totp_secret("GEZDG")


def test_autologin_only_acts_when_reauthorization_is_required(tmp_path: Path) -> None:
    autologin, store, client, calls, _clock = _setup(tmp_path)
    assert autologin.step("work")["action"] == "not-enrolled"
    autologin.enroll("work", username="user@work.example", password="pw", totp_secret=RFC_SECRET)
    store.put(client.record_id, {"refresh_token": "old", "access_token": "a"})
    assert autologin.step("work")["action"] == "healthy"
    assert calls == []

    store.put(
        client.record_id,
        {"refresh_token": "old", "oauth_failure": {"reauthorization_required": True}},
    )
    assert autologin.step("work")["action"] == "reauthorized"
    assert calls[0]["code"] == "ABCD1234"
    assert calls[0]["username"] == "user@work.example"
    assert len(calls[0]["totp"]) == 6
    assert store.get(client.record_id)["refresh_token"] == "new"
    status = autologin.status("work")
    assert status["consecutive_failures"] == 0
    assert status["last_success_at"]
    assert "password" not in status and "totp_secret" not in status


def test_autologin_never_reuses_an_accepted_totp_window(tmp_path: Path) -> None:
    autologin, _store, _client, _calls, clock = _setup(tmp_path)
    autologin.enroll("work", username="u@work.example", password="pw", totp_secret=RFC_SECRET)
    first = autologin._next_totp("work")
    code = first()
    step = int(clock()) // 30
    second = autologin._next_totp("work")()
    assert int(clock()) // 30 == step + 1
    assert second != code or totp(RFC_SECRET, step + 1) == code


def test_autologin_backs_off_then_disables_after_repeated_failures(tmp_path: Path) -> None:
    def broken(**_kwargs):
        raise AutoLoginError("unknown page")

    autologin, _store, _client, _calls, clock = _setup(tmp_path, browser=broken)
    autologin.enroll("work", username="u@work.example", password="pw", totp_secret=RFC_SECRET)
    assert autologin.step("work")["action"] == "failed"
    assert autologin.step("work")["action"] == "backing-off"
    clock.sleep(1860)
    assert autologin.step("work")["action"] == "failed"
    clock.sleep(3540)
    assert autologin.step("work")["action"] == "backing-off"
    clock.sleep(120)
    assert autologin.step("work")["action"] == "failed"
    result = autologin.step("work", force=True)
    assert result["action"] == "disabled"
    assert "3 consecutive" in result["reason"]
    # An administrator resumes it without re-entering the credentials.
    autologin.enable("work")
    status = autologin.status("work")
    assert (status["disabled_reason"], status["consecutive_failures"]) == (None, 0)
    assert autologin.step("work", force=True)["action"] == "failed"


def test_rejected_credentials_disable_immediately_until_reenrolled(tmp_path: Path) -> None:
    def rejected(**_kwargs):
        raise AutoLoginRejected("your account or password is incorrect")

    autologin, store, _client, _calls, clock = _setup(tmp_path, browser=rejected)
    autologin.enroll("work", username="u@work.example", password="bad", totp_secret=RFC_SECRET)
    assert autologin.step("work")["action"] == "disabled"
    clock.sleep(172800)
    assert autologin.step("work")["action"] == "disabled"
    autologin.enroll("work", username="u@work.example", password="good", totp_secret=RFC_SECRET)
    assert autologin.status("work")["disabled_reason"] is None
    autologin.forget("work")
    assert "password" not in store.get(record_id("work"))
    assert autologin.step("work")["action"] == "disabled"
    with pytest.raises(AutoLoginError, match="enroll again"):
        autologin.enable("work")


def test_unfinished_device_authorization_counts_as_failure(tmp_path: Path) -> None:
    autologin, _store, client, _calls, _clock = _setup(tmp_path)
    client.result = "authorization_declined"
    autologin.enroll("work", username="u@work.example", password="pw", totp_secret=RFC_SECRET)
    result = autologin.step("work")
    assert result["action"] == "failed"
    assert autologin.status("work")["consecutive_failures"] == 1
    assert record_id("work") == "mfa-autologin:work"


def _cli(monkeypatch, autologin, *argv, stdin: str = "") -> tuple[int, str]:
    import io

    from apps.mfa_autologin import main as cli

    out = io.StringIO()
    monkeypatch.setattr(cli, "build", lambda **_kwargs: autologin)
    monkeypatch.setattr("sys.argv", ["mfa-autologin", *argv])
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    monkeypatch.setattr("sys.stdout", out)
    return cli.main(), out.getvalue()


def test_cli_enrolls_from_stdin_and_manages_the_record(tmp_path: Path, monkeypatch) -> None:
    import json

    autologin, store, client, _calls, _clock = _setup(tmp_path)
    payload = json.dumps({"username": "u@work.example", "password": "pw", "totp": RFC_SECRET})
    code, out = _cli(monkeypatch, autologin, "enroll", "work", "--stdin", stdin=payload)
    assert code == 0 and "pw" not in out and json.loads(out)["enrolled"] is True

    store.put(client.record_id, {"refresh_token": "ok"})
    code, out = _cli(monkeypatch, autologin, "run", "--once")
    assert code == 0 and json.loads(out)[0]["action"] == "healthy"
    code, out = _cli(monkeypatch, autologin, "run", "--force", "work")
    assert code == 0 and json.loads(out)["action"] == "reauthorized"

    code, out = _cli(monkeypatch, autologin, "status")
    assert code == 0 and json.loads(out)[0]["last_success_at"]
    code, out = _cli(monkeypatch, autologin, "disable", "work")
    assert json.loads(out)["disabled_reason"] == "disabled by administrator"
    code, out = _cli(monkeypatch, autologin, "run", "--force", "work")
    assert code == 1
    code, out = _cli(monkeypatch, autologin, "forget", "work")
    assert code == 0 and "password" not in store.get(record_id("work"))


def test_cli_enrolls_interactively(tmp_path: Path, monkeypatch) -> None:
    autologin, _store, _client, _calls, _clock = _setup(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt: "u@work.example")
    secrets_ = iter(["pw", RFC_SECRET])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(secrets_))
    code, _out = _cli(monkeypatch, autologin, "enroll", "work")
    assert code == 0 and autologin.status("work")["username"] == "u@work.example"
    with pytest.raises(ValueError, match="Microsoft OAuth accounts"):
        autologin.enroll("gmail", username="u@work.example", password="pw", totp_secret=RFC_SECRET)


def test_cli_service_loop_logs_actions_and_refuses_non_owners(tmp_path: Path, monkeypatch) -> None:
    import types

    from apps.mfa_autologin import main as cli

    real_build = cli.build
    autologin, _store, _client, _calls, _clock = _setup(tmp_path)
    autologin.enroll("work", username="u@work.example", password="pw", totp_secret=RFC_SECRET)
    monkeypatch.setattr(cli.tempfile, "gettempdir", lambda: str(tmp_path))

    def stop(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", stop)
    with pytest.raises(KeyboardInterrupt):
        _cli(monkeypatch, autologin, "run")
    assert (tmp_path / "mfa-autologin-heartbeat").exists()
    assert autologin.status("work")["last_success_at"]

    settings = types.SimpleNamespace(
        mfa_autologin_enabled=True, mode="read-only", host_id="a", active_writer="a"
    )
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    with pytest.raises(RuntimeError, match="active production credential owner"):
        real_build()


def _build_settings(tmp_path: Path, **overrides):
    import types

    from evergarden.auth.credential_store import encode_key

    key_file = tmp_path / "key"
    key_file.write_text(encode_key(generate_key()))
    key_file.chmod(0o600)
    config = tmp_path / "accounts.json"
    config.write_text(
        json.dumps(
            account_config_payload(
                (
                    AccountConfig(
                        alias="work",
                        address="u@university.example",
                        imap_host="outlook.office365.com",
                        smtp_host="smtp.office365.com",
                        auth_kind="oauth2",
                        credential_record="microsoft:work",
                        archive_folder="Archive",
                        safe_move_folders=("Archive",),
                    ),
                    AccountConfig(
                        alias="gmail",
                        address="u@gmail.example",
                        imap_host="imap.gmail.com",
                        smtp_host="smtp.gmail.com",
                        credential_record="password:gmail",
                        archive_folder="Archive",
                        safe_move_folders=("Archive",),
                    ),
                )
            )
        )
    )
    config.chmod(0o600)
    values = {
        "mfa_autologin_enabled": True,
        "mode": "production",
        "host_id": "host-a",
        "active_writer": "host-a",
        "oauth_callback_enabled": True,
        "log_level": "INFO",
        "credential_db": tmp_path / "secrets" / "credentials.db",
        "credential_key_file": key_file,
        "account_config_file": config,
        "report_dir": tmp_path / "reports",
        "microsoft_oauth_client_id": "11111111-2222-3333-4444-555555555555",
        "microsoft_oauth_tenant": "organizations",
        "microsoft_oauth_redirect_uri": "http://127.0.0.1:8788/oauth/callback/microsoft",
        "microsoft_oauth_flow": "device_code",
        "microsoft_oauth_app_name": "Example Mail",
        "mfa_extra_allowed_host_list": ("adfs.university.example",),
        "mfa_browser_locale": "en-GB",
    }
    values.update(overrides)
    (tmp_path / "secrets").mkdir(exist_ok=True)
    return types.SimpleNamespace(**values)


def test_build_wires_configured_hosts_app_name_and_locale(tmp_path: Path, monkeypatch) -> None:
    from apps.mfa_autologin import main as cli

    monkeypatch.setattr(cli, "get_settings", lambda: _build_settings(tmp_path))
    autologin = cli.build()
    assert list(autologin.clients) == ["work"]
    assert autologin.clients["work"].uses_device_authorization
    browser = autologin.browser_login
    assert "adfs.university.example" in browser.allowed_hosts
    assert browser.expected_app_name == "example mail"
    assert browser.locale == "en-GB"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"mfa_autologin_enabled": False}, "EVERGARDEN_MFA_AUTOLOGIN_ENABLED"),
        ({"microsoft_oauth_flow": "authorization_code"}, "EVERGARDEN_MICROSOFT_OAUTH_FLOW"),
        (
            {"microsoft_oauth_client_id": MICROSOFT_CLIENT_ID_PLACEHOLDER},
            "register your own Microsoft Entra app",
        ),
    ],
)
def test_build_refuses_until_explicitly_configured(
    tmp_path: Path, monkeypatch, overrides, message
) -> None:
    from apps.mfa_autologin import main as cli

    monkeypatch.setattr(cli, "get_settings", lambda: _build_settings(tmp_path, **overrides))
    with pytest.raises(RuntimeError, match=message):
        cli.build()


@pytest.mark.parametrize(
    "overrides",
    [
        {"mfa_autologin_enabled": False},
        {"microsoft_oauth_flow": "authorization_code"},
        {"microsoft_oauth_client_id": MICROSOFT_CLIENT_ID_PLACEHOLDER},
    ],
)
def test_inspection_commands_work_with_the_feature_switched_off(
    tmp_path: Path, monkeypatch, overrides
) -> None:
    import io

    from apps.mfa_autologin import main as cli

    settings = _build_settings(tmp_path, **overrides)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    autologin = cli.build(inspection_only=True)
    autologin.enroll("work", username="u@work.example", password="pw", totp_secret=RFC_SECRET)

    for argv in (["status"], ["disable", "work"], ["forget", "work"]):
        out = io.StringIO()
        monkeypatch.setattr("sys.argv", ["mfa-autologin", *argv])
        monkeypatch.setattr("sys.stdout", out)
        assert cli.main() == 0
    assert "password" not in autologin.store.get(record_id("work"))
    for argv in (["run", "--once"], ["enroll", "work"], ["enable", "work"]):
        monkeypatch.setattr("sys.argv", ["mfa-autologin", *argv])
        with pytest.raises(RuntimeError):
            cli.main()
