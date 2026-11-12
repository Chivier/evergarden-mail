from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import re
import secrets
import urllib.parse
from typing import Any

import httpx

from evergarden.auth.credential_store import CredentialNotFound, CredentialStore
from evergarden.auth.provider_oauth import (
    AuthorizationRequest,
    OAuthConfigurationError,
    OAuthTokenRequestError,
    _now,
    _parse_expiry,
    oauth_record_lock,
)

GOOGLE_APPLICATION_RECORD = "google:oauth-application"
GOOGLE_MAIL_SCOPE = "https://mail.google.com/"
GOOGLE_SCOPES = ("openid", "email", GOOGLE_MAIL_SCOPE)
GOOGLE_AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"  # noqa: S105 - fixed public endpoint
GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

LOGGER = logging.getLogger(__name__)


class GoogleConfigurationError(OAuthConfigurationError):
    pass


class GoogleIdentityError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class GoogleApplication:
    client_id: str
    client_secret: str = dataclasses.field(repr=False)
    redirect_uris: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> GoogleApplication:
        # Accept only Google's downloaded Web application document. Endpoints
        # from the document are never used; all requests use fixed Google URLs.
        web = value.get("web") if isinstance(value, dict) else None
        if not isinstance(web, dict):
            raise GoogleConfigurationError(
                "GOOGLE_OAUTH_CLIENT_TYPE: the Google OAuth configuration must be the client JSON of a Web application"
            )
        client_id, secret, redirects = (
            web.get("client_id"),
            web.get("client_secret"),
            web.get("redirect_uris"),
        )
        if (
            not isinstance(client_id, str)
            or not re.fullmatch(r"[a-zA-Z0-9_-]{1,180}\.apps\.googleusercontent\.com", client_id)
            or not isinstance(secret, str)
            or not 1 <= len(secret) <= 4096
            or any(char.isspace() or ord(char) < 32 for char in secret)
            or not isinstance(redirects, list)
            or not 1 <= len(redirects) <= 32
        ):
            raise GoogleConfigurationError(
                "GOOGLE_OAUTH_CLIENT_INVALID: the Google OAuth client configuration is malformed"
            )
        for uri in redirects:
            if not isinstance(uri, str) or len(uri) > 2048:
                raise GoogleConfigurationError(
                    "GOOGLE_OAUTH_REDIRECT_INVALID: the Google OAuth redirect URI is malformed"
                )
            parsed = urllib.parse.urlsplit(uri)
            loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            if (
                not parsed.netloc
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
            ):
                raise GoogleConfigurationError(
                    "GOOGLE_OAUTH_REDIRECT_HTTPS: the Google OAuth redirect URI must use HTTPS"
                )
        return cls(client_id, secret, tuple(redirects))

    def private_payload(self) -> dict[str, Any]:
        return {
            "web": {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uris": list(self.redirect_uris),
            }
        }


class GoogleOAuthClient:
    """Account-bound Gmail authorization and refresh with encrypted local storage."""

    provider = "google"
    uses_device_authorization = False
    flow = "authorization_code"
    app_name = ""

    def __init__(
        self,
        *,
        store: CredentialStore,
        record_id: str,
        expected_address: str,
        redirect_uri: str,
        http: httpx.Client | None = None,
    ):
        self.store, self.record_id = store, record_id
        self.expected_address, self.redirect_uri = expected_address, redirect_uri
        self.http = http or httpx.Client(follow_redirects=False)

    def _application(self) -> GoogleApplication:
        try:
            value = self.store.get(GOOGLE_APPLICATION_RECORD)
        except CredentialNotFound as exc:
            raise GoogleConfigurationError(
                "GOOGLE_OAUTH_NOT_CONFIGURED: no Google OAuth app is configured yet; import the client configuration first"
            ) from exc
        app = GoogleApplication.parse(value)
        if self.redirect_uri not in app.redirect_uris:
            raise GoogleConfigurationError(
                "GOOGLE_OAUTH_REDIRECT_UNREGISTERED: the Google OAuth client does not list the current redirect URI"
            )
        return app

    @property
    def configured(self) -> bool:
        try:
            self._application()
        except GoogleConfigurationError:
            return False
        return True

    @property
    def authorization_binding(self) -> str:
        value = (
            self._application().client_id,
            self.redirect_uri,
            self.expected_address.casefold(),
            self.record_id,
        )
        return hashlib.sha256(json.dumps(value).encode()).hexdigest()

    def build_authorization_request(self, *, lifetime_seconds: int = 600) -> AuthorizationRequest:
        app = self._application()
        verifier, state = secrets.token_urlsafe(64), secrets.token_urlsafe(32)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        params = {
            "client_id": app.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(GOOGLE_SCOPES),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent select_account",
            "login_hint": self.expected_address,
        }
        return AuthorizationRequest(
            url=f"{GOOGLE_AUTHORIZE_ENDPOINT}?{urllib.parse.urlencode(params)}",
            state=state,
            code_verifier=verifier,
            expires_at=_now() + dt.timedelta(seconds=lifetime_seconds),
        )

    def exchange_code(self, *, code: str, code_verifier: str) -> dict[str, Any]:
        with oauth_record_lock(self.store, self.record_id):
            app = self._application()
            response = self.http.post(
                GOOGLE_TOKEN_ENDPOINT,
                data={
                    "client_id": app.client_id,
                    "client_secret": app.client_secret,
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": code_verifier,
                    "redirect_uri": self.redirect_uri,
                },
                timeout=30,
            )
            value = self._token_response(response, prior={})
            # The login hint is not an identity check. Verify the actual token
            # owner through Google's HTTPS endpoint before replacing any record.
            identity_response = self.http.get(
                GOOGLE_USERINFO_ENDPOINT,
                headers={"Authorization": f"Bearer {value['access_token']}"},
                timeout=15,
            )
            if identity_response.status_code != 200:
                self._revoke_discarded_grant(value)
                raise GoogleIdentityError(
                    "GOOGLE_IDENTITY_UNVERIFIED: could not verify the Google mailbox identity; authorize again"
                )
            try:
                identity = identity_response.json()
            except ValueError as exc:
                self._revoke_discarded_grant(value)
                raise GoogleIdentityError(
                    "GOOGLE_IDENTITY_MALFORMED: the Google identity response is malformed"
                ) from exc
            if (
                not isinstance(identity, dict)
                or identity.get("email_verified") is not True
                or not isinstance(identity.get("email"), str)
                or identity["email"].casefold() != self.expected_address.casefold()
                or not isinstance(identity.get("sub"), str)
                or not re.fullmatch(r"[\x21-\x7e]{1,255}", identity["sub"])
            ):
                self._revoke_discarded_grant(value)
                raise GoogleIdentityError(
                    "GOOGLE_ACCOUNT_MISMATCH: the signed-in Google account does not match the selected mailbox; authorize again with that mailbox"
                )
            stored = {
                **value,
                "provider": self.provider,
                "client_id": app.client_id,
                "email": self.expected_address,
                "subject": identity["sub"],
            }
            self.store.put(self.record_id, stored)
            return stored

    def _revoke_discarded_grant(self, value: dict[str, Any]) -> None:
        """Best-effort provider-side revocation of a grant we refuse to store.

        A full-scope refresh token must not stay valid at Google with nothing
        tracking it locally. Failure to revoke never masks the identity error.
        """
        token = value.get("refresh_token") or value.get("access_token")
        if not token:
            return
        try:
            response = self.http.post(GOOGLE_REVOKE_ENDPOINT, data={"token": token}, timeout=15)
            if response.status_code != 200:
                LOGGER.warning(
                    "google oauth discarded grant revocation rejected status=%s record=%s",
                    response.status_code,
                    self.record_id,
                )
        except Exception as exc:
            LOGGER.warning(
                "google oauth discarded grant revocation failed error_class=%s record=%s",
                type(exc).__name__,
                self.record_id,
            )

    def _check_record(self, record: dict, app: GoogleApplication) -> None:
        if (
            record.get("provider") != self.provider
            or record.get("client_id") != app.client_id
            or str(record.get("email", "")).casefold() != self.expected_address.casefold()
            or not record.get("subject")
        ):
            raise GoogleIdentityError(
                "GOOGLE_GRANT_CHANGED: the Google mailbox or app configuration changed; authorize again"
            )

    def authorization_required(self, record: dict) -> bool:
        if not record.get("refresh_token") or (record.get("oauth_failure") or {}).get(
            "reauthorization_required"
        ):
            return True
        try:
            self._check_record(record, self._application())
        except (GoogleConfigurationError, GoogleIdentityError):
            return True
        return False

    def access_token(
        self, *, refresh_margin_seconds: int = 300, force_refresh: bool = False
    ) -> str:
        with oauth_record_lock(self.store, self.record_id):
            app, prior = self._application(), self.store.get(self.record_id)
            self._check_record(prior, app)
            if (prior.get("oauth_failure") or {}).get("reauthorization_required"):
                raise GoogleIdentityError(
                    "GOOGLE_GRANT_REVOKED: the Google authorization is no longer valid; connect the mailbox again"
                )
            expires = _parse_expiry(prior.get("expires_at"))
            token = prior.get("access_token")
            if (
                not force_refresh
                and token
                and expires
                and expires > _now() + dt.timedelta(seconds=refresh_margin_seconds)
            ):
                return str(token)
            return str(self._refresh_unlocked(app, prior)["access_token"])

    def refresh(self) -> dict[str, Any]:
        with oauth_record_lock(self.store, self.record_id):
            app, prior = self._application(), self.store.get(self.record_id)
            self._check_record(prior, app)
            return self._refresh_unlocked(app, prior)

    def _refresh_unlocked(self, app: GoogleApplication, prior: dict) -> dict[str, Any]:
        if not prior.get("refresh_token"):
            raise GoogleIdentityError(
                "GOOGLE_REAUTH_REQUIRED: the Google mailbox needs to be authorized again"
            )
        response = self.http.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "client_id": app.client_id,
                "client_secret": app.client_secret,
                "grant_type": "refresh_token",
                "refresh_token": prior["refresh_token"],
            },
            timeout=30,
        )
        stored = self._token_response(response, prior=prior)
        self.store.put(self.record_id, stored)
        return stored

    def _token_response(self, response: httpx.Response, *, prior: dict) -> dict[str, Any]:
        try:
            value = response.json()
        except ValueError as exc:
            raise RuntimeError("Google OAuth response is malformed") from exc
        if not isinstance(value, dict):
            raise RuntimeError("Google OAuth response is malformed")
        if response.status_code != 200:
            allowed = {
                "invalid_grant",
                "invalid_client",
                "invalid_scope",
                "invalid_request",
                "unauthorized_client",
                "access_denied",
                "admin_policy_enforced",
                "temporarily_unavailable",
                "server_error",
            }
            error = value.get("error")
            error = error if isinstance(error, str) and error in allowed else "token_request_failed"
            failure = OAuthTokenRequestError(response.status_code, error, [], provider="Google")
            if error in {"access_denied", "admin_policy_enforced"}:
                failure.reauthorization_required = True
            if prior:
                self.store.put(
                    self.record_id,
                    {
                        **prior,
                        "oauth_failure": {
                            "error": error,
                            "error_codes": [],
                            "reauthorization_required": failure.reauthorization_required,
                        },
                    },
                )
            raise failure
        token, refresh = (
            value.get("access_token"),
            value.get("refresh_token") or prior.get("refresh_token"),
        )
        if any(
            not isinstance(item, str)
            or not 1 <= len(item) <= 65536
            or any(char.isspace() or ord(char) < 32 for char in item)
            for item in (token, refresh)
        ):
            raise RuntimeError("Google OAuth response lacks valid access and refresh tokens")
        expiry = value.get("expires_in")
        if type(expiry) is not int or not 1 <= expiry <= 86400:
            raise RuntimeError("Google OAuth token expiry is malformed")
        if str(value.get("token_type", "")).casefold() != "bearer":
            raise RuntimeError("Google OAuth token type is unsupported")
        scope = value.get("scope", prior.get("scope", ""))
        if not isinstance(scope, str) or GOOGLE_MAIL_SCOPE not in scope.split():
            raise RuntimeError("Google OAuth token is missing the required Gmail scope")
        return {
            **{key: item for key, item in prior.items() if key != "oauth_failure"},
            "access_token": token,
            "refresh_token": refresh,
            "scope": scope,
            "token_type": "Bearer",
            "expires_at": (_now() + dt.timedelta(seconds=expiry)).isoformat(),
        }
