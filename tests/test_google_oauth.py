from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import imaplib
import json
import urllib.parse

import httpx
import pytest
from account_fixtures import TEST_ACCOUNTS
from fastapi.testclient import TestClient

from apps.approval_ui.main import create_app
from evergarden.approvals.service import ApprovalRepository, ApprovalService
from evergarden.auth.admin_session import SESSION_COOKIE, AdminSessionAuth
from evergarden.auth.credential_store import (
    CredentialNotFound,
    CredentialStore,
    encode_key,
    generate_key,
)
from evergarden.auth.google_oauth import (
    GOOGLE_APPLICATION_RECORD,
    GOOGLE_MAIL_SCOPE,
    GOOGLE_REVOKE_ENDPOINT,
    GOOGLE_SCOPES,
    GOOGLE_TOKEN_ENDPOINT,
    GOOGLE_USERINFO_ENDPOINT,
    GoogleApplication,
    GoogleConfigurationError,
    GoogleIdentityError,
    GoogleOAuthClient,
)
from evergarden.auth.maintenance import OAuthMaintenance
from evergarden.auth.oauth_coordinator import OAuthCoordinator, OAuthStateError
from evergarden.auth.provider_oauth import OAuthTokenRequestError
from evergarden.config import Settings
from evergarden.mail.credential_admin import ProviderCredentialError, import_google_client
from evergarden.mail.models import (
    account_config_payload,
    parse_account_config_payload,
)
from evergarden.mail.runtime import MailRuntime
from evergarden.mail.xoauth2 import xoauth2_response

ADDRESS = "person@company.test"
CALLBACK = "https://mail.example.test/oauth/callback/google"
APPLICATION = {
    "web": {
        "client_id": "test-client.apps.googleusercontent.com",
        "client_secret": "app-secret-test",
        "redirect_uris": [CALLBACK],
    }
}


class GoogleHttp:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def post(self, url, *, data, timeout):
        self.calls.append((url, dict(data)))
        return self.responses.pop(0)

    def get(self, url, *, headers, timeout):
        self.calls.append((url, dict(headers)))
        return self.responses.pop(0)


def tokens(**changes):
    return httpx.Response(
        200,
        json={
            "access_token": "access-test",
            "refresh_token": "refresh-test",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": " ".join(GOOGLE_SCOPES),
            **changes,
        },
    )


def identity(**changes):
    return httpx.Response(
        200, json={"email": ADDRESS, "email_verified": True, "sub": "123456789", **changes}
    )


def setup(tmp_path, responses=()):
    store = CredentialStore(
        tmp_path / "secrets" / "credentials.db", key=generate_key(), host_id="test"
    )
    store.put(GOOGLE_APPLICATION_RECORD, APPLICATION)
    http = GoogleHttp(responses)
    client = GoogleOAuthClient(
        store=store,
        record_id="google:company",
        expected_address=ADDRESS,
        redirect_uri=CALLBACK,
        http=http,
    )
    return store, client, http


def test_google_authorization_is_pkce_offline_and_bound_to_selected_mailbox(tmp_path):
    _store, client, http = setup(tmp_path)
    request = client.build_authorization_request()
    url = urllib.parse.urlsplit(request.url)
    query = urllib.parse.parse_qs(url.query)
    assert (url.scheme, url.hostname, url.path) == (
        "https",
        "accounts.google.com",
        "/o/oauth2/v2/auth",
    )
    assert query["login_hint"] == [ADDRESS]
    assert query["access_type"] == ["offline"]
    assert query["prompt"] == ["consent select_account"]
    assert query["code_challenge_method"] == ["S256"]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(request.code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert query["code_challenge"] == [challenge]
    assert GOOGLE_MAIL_SCOPE in query["scope"][0].split()
    assert "app-secret-test" not in request.url
    assert http.calls == []


def test_exchange_refresh_restart_and_no_secret_disclosure(tmp_path, caplog):
    store, client, http = setup(tmp_path, [tokens(), identity(), tokens(refresh_token=None)])
    value = client.exchange_code(code="code-test", code_verifier="verifier-test")
    assert value["subject"] == "123456789"
    assert http.calls[0][0] == GOOGLE_TOKEN_ENDPOINT
    assert http.calls[0][1]["client_secret"] == "app-secret-test"
    assert http.calls[1] == (GOOGLE_USERINFO_ENDPOINT, {"Authorization": "Bearer access-test"})
    assert client.access_token() == "access-test"
    assert len(http.calls) == 2
    refreshed = client.refresh()
    assert refreshed["refresh_token"] == "refresh-test"
    assert http.calls[2][1]["grant_type"] == "refresh_token"
    restarted = GoogleOAuthClient(
        store=store,
        record_id=client.record_id,
        expected_address=ADDRESS,
        redirect_uri=CALLBACK,
        http=GoogleHttp([]),
    )
    assert restarted.access_token() == "access-test"
    for secret in ("access-test", "refresh-test", "app-secret-test"):
        assert secret not in caplog.text
        assert secret.encode() not in store.path.read_bytes()
        assert secret not in repr(GoogleApplication.parse(APPLICATION))


@pytest.mark.parametrize(
    "claims",
    [
        {"email": "wrong@company.test"},
        {"email_verified": False},
        {"email_verified": "true"},
        {"sub": ""},
    ],
)
def test_wrong_or_unverified_identity_never_overwrites_previous_credentials(tmp_path, claims):
    store, client, http = setup(
        tmp_path, [tokens(), identity(**claims), httpx.Response(200, json={})]
    )
    store.put(client.record_id, {"previous": "unchanged"})
    with pytest.raises(GoogleIdentityError, match="GOOGLE_ACCOUNT_MISMATCH"):
        client.exchange_code(code="code-test", code_verifier="verifier-test")
    assert store.get(client.record_id) == {"previous": "unchanged"}
    # The discarded full-scope grant is revoked at Google, not left dangling.
    revoke = http.calls[-1]
    assert revoke[0] == GOOGLE_REVOKE_ENDPOINT
    assert revoke[1] == {"token": "refresh-test"}


def test_revocation_failure_never_masks_the_identity_error(tmp_path):
    store, client, _http = setup(tmp_path, [tokens(), identity(email="other@example.test")])
    # The revoke POST has no queued response and raises inside the fake; the
    # identity error must still surface and nothing may be stored.
    with pytest.raises(GoogleIdentityError, match="GOOGLE_ACCOUNT_MISMATCH"):
        client.exchange_code(code="code-test", code_verifier="verifier-test")
    with pytest.raises(CredentialNotFound):
        store.get(client.record_id)


@pytest.mark.parametrize(
    "changes",
    [
        {"scope": "openid email"},
        {"refresh_token": None},
        {"access_token": "bad\nheader"},
        {"expires_in": False},
        {"token_type": "MAC"},
    ],
)
def test_incomplete_google_grants_fail_without_persistence(tmp_path, changes):
    store, client, http = setup(tmp_path, [tokens(**changes)])
    with pytest.raises(RuntimeError):
        client.exchange_code(code="code-test", code_verifier="verifier-test")
    with pytest.raises(CredentialNotFound):
        store.get(client.record_id)
    assert len(http.calls) == 1


def test_refresh_preserves_scope_and_rotation_but_stops_on_revocation(tmp_path):
    store, client, http = setup(
        tmp_path,
        [
            tokens(),
            identity(),
            httpx.Response(
                200,
                json={"access_token": "rotated-access", "expires_in": 3600, "token_type": "Bearer"},
            ),
            httpx.Response(
                400, json={"error": "invalid_grant", "error_description": "private detail"}
            ),
        ],
    )
    client.exchange_code(code="test-code", code_verifier="test-verifier")
    assert client.access_token(force_refresh=True) == "rotated-access"
    assert store.get(client.record_id)["scope"] == " ".join(GOOGLE_SCOPES)
    with pytest.raises(OAuthTokenRequestError, match=r"Google.*invalid_grant") as error:
        client.refresh()
    assert "private detail" not in str(error.value)
    assert store.get(client.record_id)["oauth_failure"]["reauthorization_required"]
    calls = len(http.calls)
    with pytest.raises(GoogleIdentityError, match="GOOGLE_GRANT_REVOKED"):
        client.access_token()
    assert len(http.calls) == calls


def test_provider_binding_expiry_and_single_use_callback(tmp_path):
    store, client, http = setup(tmp_path, [tokens(), identity()])
    coordinator = OAuthCoordinator(store=store, clients={"company": client})
    started = coordinator.start("company")
    with pytest.raises(OAuthStateError, match="provider"):
        coordinator.callback(state=started["state"], code="code-test", provider="microsoft")
    assert not store.get(coordinator._record_id(started["state"]))["consumed"]
    assert http.calls == []
    assert (
        coordinator.callback(state=started["state"], code="code-test", provider="google")["status"]
        == "authorized"
    )
    with pytest.raises(OAuthStateError, match="consumed"):
        coordinator.callback(state=started["state"], code="code-test", provider="google")
    assert len(http.calls) == 2
    expired = coordinator.start("company")
    coordinator.now = lambda: dt.datetime.now(dt.UTC) + dt.timedelta(minutes=11)
    with pytest.raises(OAuthStateError, match="expired"):
        coordinator.callback(state=expired["state"], code="code-test", provider="google")


def test_pending_authorization_rejects_changed_client_or_mailbox(tmp_path):
    store, client, http = setup(tmp_path)
    coordinator = OAuthCoordinator(store=store, clients={"company": client})
    state = coordinator.start("company")["state"]
    client.expected_address = "changed@company.test"
    with pytest.raises(OAuthStateError, match="configuration"):
        coordinator.callback(state=state, code="code-test", provider="google")
    assert http.calls == []


def test_google_application_import_enforces_private_files_and_registered_redirect(tmp_path):
    store, _client, _http = setup(tmp_path)
    path = tmp_path / "client.json"
    path.write_text(json.dumps(APPLICATION))
    path.chmod(0o644)
    with pytest.raises(ProviderCredentialError, match="0600"):
        import_google_client(store, path, redirect_uri=CALLBACK)
    path.chmod(0o600)
    assert import_google_client(store, path, redirect_uri=CALLBACK) == 2
    link = tmp_path / "symlink.json"
    link.symlink_to(path)
    with pytest.raises(ProviderCredentialError):
        import_google_client(store, link, redirect_uri=CALLBACK)
    with pytest.raises(GoogleConfigurationError, match="redirect URI"):
        import_google_client(
            store, path, redirect_uri="https://different.test/oauth/callback/google"
        )
    with pytest.raises(GoogleConfigurationError, match="Web"):
        GoogleApplication.parse({"installed": APPLICATION["web"]})


def runtime_settings(tmp_path):
    key_file = tmp_path / "key"
    key_file.write_text(encode_key(generate_key()))
    key_file.chmod(0o600)
    session_key_file = tmp_path / "session-key"
    session_key_file.write_text(base64.urlsafe_b64encode(generate_key()).rstrip(b"=").decode())
    session_key_file.chmod(0o600)
    config = tmp_path / "accounts.json"
    company = dataclasses.replace(
        TEST_ACCOUNTS[2],
        alias="company",
        auth_kind="oauth2",
        credential_record="google:company",
        address=ADDRESS,
        enabled=False,
    )
    config.write_text(json.dumps(account_config_payload((TEST_ACCOUNTS[1], company))))
    config.chmod(0o600)
    return Settings(
        credential_db=tmp_path / "secrets" / "db",
        credential_key_file=key_file,
        account_config_file=config,
        archive_dir=tmp_path / "archive",
        google_oauth_redirect_uri=CALLBACK,
        admin_session_key_file=session_key_file,
        oauth_callback_enabled=True,
        admin_secure_cookies=False,
    )


def test_disabled_google_mailbox_can_authorize_but_cannot_sync_or_execute(tmp_path):
    runtime = MailRuntime(runtime_settings(tmp_path))
    assert set(runtime.oauth_clients) == {"outlook"}
    assert set(runtime.oauth_authorization_clients()) == {"company", "outlook"}
    assert set(runtime.actions.accounts) == {"outlook"}
    with pytest.raises(ValueError, match="disabled"):
        runtime.sync_selected("company")
    assert runtime.oauth_authorization_clients()["company"].configured is False
    with pytest.raises(GoogleConfigurationError, match="GOOGLE_OAUTH_NOT_CONFIGURED"):
        runtime.oauth_authorization_clients()["company"].build_authorization_request()
    config = account_config_payload(
        (dataclasses.replace(TEST_ACCOUNTS[2], auth_kind="oauth2", smtp_host="wrong.test"),)
    )
    with pytest.raises(RuntimeError, match="Gmail"):
        parse_account_config_payload(config)


def test_google_ui_admin_csrf_callback_and_clear_configuration_error(tmp_path):
    settings = runtime_settings(tmp_path)
    runtime = MailRuntime(settings)
    coordinator = OAuthCoordinator(
        store=runtime.store, clients=runtime.oauth_authorization_clients()
    )
    auth = AdminSessionAuth(session_key_file=settings.admin_session_key_file)
    app = create_app(
        settings,
        approvals=ApprovalService(ApprovalRepository()),
        oauth=coordinator,
        admin_auth=auth,
    )
    web = TestClient(app)
    assert web.get("/oauth/callback/google?state=x&code=y").status_code == 401
    web.cookies.set(SESSION_COOKIE, auth.issue("admin")[0])
    accounts = web.get("/oauth/accounts").json()
    assert accounts["providers"]["company"] == "google"
    assert accounts["configured"]["company"] is False
    assert web.post("/oauth/start/company").status_code == 403
    csrf = web.get("/session?surface=oauth").json()["csrf"]
    response = web.post("/oauth/start/company", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 503
    assert "GOOGLE_OAUTH_NOT_CONFIGURED" in response.json()["detail"]
    runtime.store.put(GOOGLE_APPLICATION_RECORD, APPLICATION)
    google = coordinator.clients["company"]
    google.http = GoogleHttp([tokens(), identity()])
    response = web.post("/oauth/start/company", headers={"X-CSRF-Token": csrf})
    state = response.json()["state"]
    assert web.get(f"/oauth/callback/microsoft?state={state}&code=test").status_code == 400
    response = web.get(f"/oauth/callback/google?state={state}&code=test", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/oauth?status=authorized&account=company"
    assert web.get(f"/oauth/callback/google?state={state}&code=test").status_code == 400


def test_google_credentials_participate_in_background_refresh(tmp_path):
    settings = runtime_settings(tmp_path)
    all_accounts = parse_account_config_payload(
        json.loads(settings.account_config_file.read_text()), include_disabled=True
    )
    runtime = MailRuntime(settings, accounts=(dataclasses.replace(all_accounts[1], enabled=True),))
    runtime.store.put(GOOGLE_APPLICATION_RECORD, APPLICATION)
    google = runtime.oauth_clients["company"]
    google.http = GoogleHttp([tokens(), identity(), tokens(access_token="background-fresh")])
    google.exchange_code(code="code-test", code_verifier="verifier-test")
    record = runtime.store.get(google.record_id)
    runtime.store.put(google.record_id, {**record, "expires_at": "2020-01-01T00:00:00+00:00"})
    assert OAuthMaintenance(runtime).step()["checked_accounts"] == ["company"]
    assert runtime.store.get(google.record_id)["access_token"] == "background-fresh"


def test_changed_google_application_requires_authorization_without_refresh_loop(tmp_path):
    settings = runtime_settings(tmp_path)
    accounts = parse_account_config_payload(
        json.loads(settings.account_config_file.read_text()), include_disabled=True
    )
    runtime = MailRuntime(settings, accounts=(dataclasses.replace(accounts[1], enabled=True),))
    runtime.store.put(GOOGLE_APPLICATION_RECORD, APPLICATION)
    google = runtime.oauth_clients["company"]
    google.http = GoogleHttp([tokens(), identity()])
    google.exchange_code(code="code-test", code_verifier="verifier-test")
    changed = {"web": {**APPLICATION["web"], "client_id": "different.apps.googleusercontent.com"}}
    runtime.store.put(GOOGLE_APPLICATION_RECORD, changed)
    assert runtime.refresh_readiness()[0]["status"] == "authorization_required"
    report = OAuthMaintenance(runtime).step()
    assert report["authorization_required"] == ["company"]
    assert report["failures"] == []
    assert len(google.http.calls) == 2


@pytest.mark.parametrize("as_bytes", [True, False])
def test_xoauth2_error_challenge_gets_empty_response(as_bytes):
    respond = xoauth2_response(ADDRESS, "token-test", as_bytes=as_bytes)
    expected = f"user={ADDRESS}\x01auth=Bearer token-test\x01\x01"
    assert respond() == (expected.encode() if as_bytes else expected)
    assert respond(b'{"status":"401"}') == (b"" if as_bytes else "")
    assert respond(b"unexpected-extra-challenge") == (b"" if as_bytes else "")


def test_gmail_sync_and_action_auth_finish_provider_error_challenge(tmp_path):
    settings = runtime_settings(tmp_path)
    company = parse_account_config_payload(
        json.loads(settings.account_config_file.read_text()), include_disabled=True
    )[1]
    runtime = MailRuntime(settings, accounts=(dataclasses.replace(company, enabled=True),))

    class RejectingImap:
        def authenticate(self, mechanism, respond):
            assert mechanism == "XOAUTH2"
            assert b"Bearer test-token" in respond(b"")
            assert respond(b'{"status":"401"}') == b""
            raise imaplib.IMAP4.error("authentication rejected")

        def logout(self):
            pass

    for connector in (runtime.sync.connector, runtime.actions.connector):
        connector.imap_factory = lambda *_args, **_kwargs: RejectingImap()
        connector.oauth_access_token = lambda _account: "test-token"
        with pytest.raises(imaplib.IMAP4.error):
            connector.authenticate_once(company, force_refresh=False)
