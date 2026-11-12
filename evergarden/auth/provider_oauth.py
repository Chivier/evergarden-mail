from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as dt
import fcntl
import hashlib
import logging
import secrets
import urllib.parse
from collections.abc import Mapping
from typing import Any, Protocol

import httpx

from evergarden.auth.credential_store import CredentialStore

logger = logging.getLogger(__name__)

# The shipped default of EVERGARDEN_MICROSOFT_OAUTH_CLIENT_ID. It is not a
# valid client: every deployment registers its own Microsoft Entra app.
MICROSOFT_CLIENT_ID_PLACEHOLDER = "replace-with-public-client-id"
MICROSOFT_OAUTH_FLOWS = ("authorization_code", "device_code")

MICROSOFT_SCOPES = (
    "offline_access",
    "https://outlook.office.com/IMAP.AccessAsUser.All",
    "https://outlook.office.com/SMTP.Send",
)


class OAuthConfigurationError(RuntimeError):
    """The provider's OAuth app is not configured; an administrator must act."""


class MicrosoftConfigurationError(OAuthConfigurationError):
    """No usable Microsoft Entra app registration is configured."""


@dataclasses.dataclass(frozen=True)
class OAuthRegistration:
    client_id: str
    tenant: str = "common"
    redirect_uri: str = "http://127.0.0.1:8788/oauth/callback/microsoft"
    scopes: tuple[str, ...] = MICROSOFT_SCOPES
    # authorization_code redirects the browser back to redirect_uri;
    # device_code shows a code to enter at Microsoft's device sign-in page.
    flow: str = "authorization_code"
    # The app's display name as Microsoft shows it on sign-in pages; empty
    # when the deployment did not declare it.
    app_name: str = ""

    def __post_init__(self) -> None:
        if self.flow not in MICROSOFT_OAUTH_FLOWS:
            raise ValueError(
                f"Microsoft OAuth flow must be one of: {', '.join(MICROSOFT_OAUTH_FLOWS)}"
            )

    @property
    def configured(self) -> bool:
        return bool(self.client_id) and self.client_id != MICROSOFT_CLIENT_ID_PLACEHOLDER

    def require_configured(self) -> None:
        if not self.configured:
            raise MicrosoftConfigurationError(
                "Microsoft OAuth is not configured: register your own Microsoft Entra app "
                "and set EVERGARDEN_MICROSOFT_OAUTH_CLIENT_ID to its client id"
            )

    @property
    def authorize_endpoint(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/authorize"

    @property
    def token_endpoint(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token"


def microsoft_registration(settings: Any) -> OAuthRegistration:
    """Build the Microsoft app registration from ``evergarden.config.Settings``."""
    return OAuthRegistration(
        client_id=settings.microsoft_oauth_client_id,
        tenant=settings.microsoft_oauth_tenant,
        redirect_uri=settings.microsoft_oauth_redirect_uri,
        flow=settings.microsoft_oauth_flow,
        app_name=settings.microsoft_oauth_app_name,
    )


@dataclasses.dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    state: str
    code_verifier: str
    expires_at: dt.datetime


class HttpPoster(Protocol):
    def post(self, url: str, *, data: Mapping[str, str], timeout: float) -> httpx.Response: ...


class OAuthTokenRequestError(RuntimeError):
    def __init__(self, status: int, error: str, error_codes: list[int], *, provider="Microsoft"):
        self.error = error
        self.error_codes = error_codes
        self.reauthorization_required = error in {
            "invalid_grant",
            "interaction_required",
            "consent_required",
        }
        codes = ", ".join(f"AADSTS{code}" for code in error_codes)
        detail = f"{error}; {codes}" if codes else error
        action = "; interactive reauthorization required" if self.reauthorization_required else ""
        super().__init__(f"{provider} OAuth token request failed ({status}): {detail}{action}")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _parse_expiry(value: Any) -> dt.datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(float(value), tz=dt.UTC)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or dt.UTC).astimezone(dt.UTC)


@contextlib.contextmanager
def oauth_record_lock(store: CredentialStore, record_id: str):
    digest = hashlib.sha256(record_id.encode()).hexdigest()[:20]
    path = store.path.parent / f".oauth-{digest}.lock"
    with path.open("a+") as handle:
        path.chmod(0o600)
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class MicrosoftOAuthClient:
    """Microsoft authorization-code/refresh foundation with no browser automation."""

    provider = "microsoft"

    def __init__(
        self,
        *,
        store: CredentialStore,
        record_id: str,
        registration: OAuthRegistration,
        http: HttpPoster | None = None,
    ):
        self.store = store
        self.record_id = record_id
        self.registration = registration
        self.http = http or httpx.Client()

    @property
    def uses_device_authorization(self) -> bool:
        return self.registration.flow == "device_code"

    @property
    def configured(self) -> bool:
        return self.registration.configured

    @property
    def flow(self) -> str:
        return self.registration.flow

    @property
    def app_name(self) -> str:
        return self.registration.app_name

    def start_device_authorization(self) -> dict[str, Any]:
        self.registration.require_configured()
        endpoint = self.registration.token_endpoint.removesuffix("/token") + "/devicecode"
        response = self.http.post(
            endpoint,
            data={
                "client_id": self.registration.client_id,
                "scope": " ".join(self.registration.scopes),
            },
            timeout=30,
        )
        if response.status_code >= 400:
            self._persist_response(response, prior={})
        try:
            value = response.json()
            device_code = value["device_code"]
            user_code = value["user_code"]
            verification_uri = value["verification_uri"]
            expires_in = int(value["expires_in"])
            interval = int(value.get("interval", 5))
        except (ValueError, TypeError, KeyError) as exc:
            raise RuntimeError("Microsoft device authorization response is malformed") from exc
        if (
            not isinstance(device_code, str)
            or not 1 <= len(device_code) <= 65536
            or not isinstance(user_code, str)
            or not 1 <= len(user_code) <= 32
            or verification_uri
            not in (
                "https://login.microsoft.com/device",
                "https://microsoft.com/devicelogin",
                "https://www.microsoft.com/devicelogin",
            )
            or not 1 <= expires_in <= 1800
            or not 1 <= interval <= 60
        ):
            raise RuntimeError("Microsoft device authorization response is malformed")
        return {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "interval": interval,
            "expires_at": (_now() + dt.timedelta(seconds=expires_in)).isoformat(),
        }

    def poll_device_authorization(self, device_code: str) -> str:
        with self._record_lock():
            response = self.http.post(
                self.registration.token_endpoint,
                data={
                    "client_id": self.registration.client_id,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                },
                timeout=30,
            )
            if response.status_code >= 400:
                try:
                    value = response.json()
                except ValueError:
                    value = {}
                error = value.get("error") if isinstance(value, dict) else None
                if error in (
                    "authorization_pending",
                    "slow_down",
                    "authorization_declined",
                    "expired_token",
                ):
                    return error
            self._persist_response(response, prior={})
            return "authorized"

    @contextlib.contextmanager
    def _record_lock(self):
        with oauth_record_lock(self.store, self.record_id):
            yield

    def build_authorization_request(self, *, lifetime_seconds: int = 600) -> AuthorizationRequest:
        self.registration.require_configured()
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        state = secrets.token_urlsafe(32)
        params = {
            "client_id": self.registration.client_id,
            "response_type": "code",
            "redirect_uri": self.registration.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(self.registration.scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return AuthorizationRequest(
            url=f"{self.registration.authorize_endpoint}?{urllib.parse.urlencode(params)}",
            state=state,
            code_verifier=verifier,
            expires_at=_now() + dt.timedelta(seconds=lifetime_seconds),
        )

    def exchange_code(self, *, code: str, code_verifier: str) -> dict[str, Any]:
        with self._record_lock():
            response = self.http.post(
                self.registration.token_endpoint,
                data={
                    "client_id": self.registration.client_id,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.registration.redirect_uri,
                    "code_verifier": code_verifier,
                    "scope": " ".join(self.registration.scopes),
                },
                timeout=30,
            )
            return self._persist_response(response, prior={})

    def refresh(self) -> dict[str, Any]:
        with self._record_lock():
            return self._refresh_unlocked()

    def _refresh_unlocked(self) -> dict[str, Any]:
        prior = self.store.get(self.record_id)
        refresh_token = prior.get("refresh_token")
        if not refresh_token:
            raise RuntimeError(
                f"OAuth record {self.record_id} requires interactive reauthorization"
            )
        response = self.http.post(
            self.registration.token_endpoint,
            data={
                "client_id": self.registration.client_id,
                "grant_type": "refresh_token",
                "refresh_token": str(refresh_token),
                "scope": " ".join(self.registration.scopes),
            },
            timeout=30,
        )
        return self._persist_response(response, prior=prior)

    def access_token(
        self, *, refresh_margin_seconds: int = 300, force_refresh: bool = False
    ) -> str:
        with self._record_lock():
            record = self.store.get(self.record_id)
            expires = _parse_expiry(
                record.get("expires_at") or record.get("access_token_expiration")
            )
            token = record.get("access_token")
            if (
                not force_refresh
                and token
                and expires
                and expires > _now() + dt.timedelta(seconds=refresh_margin_seconds)
            ):
                return str(token)
            refreshed = self._refresh_unlocked()
            return str(refreshed["access_token"])

    def _persist_response(
        self, response: httpx.Response, *, prior: dict[str, Any]
    ) -> dict[str, Any]:
        if response.status_code >= 400:
            try:
                value = response.json()
            except ValueError:
                value = {}
            value = value if isinstance(value, dict) else {}
            error = value.get("error")
            allowed_errors = (
                "invalid_grant",
                "interaction_required",
                "consent_required",
                "invalid_client",
                "invalid_scope",
                "temporarily_unavailable",
                "server_error",
                "invalid_request",
                "unauthorized_client",
            )
            error = error if error in allowed_errors else "token_request_failed"
            raw_codes = value.get("error_codes", [])
            codes = (
                [code for code in raw_codes if type(code) is int and 0 < code < 10_000_000][:5]
                if isinstance(raw_codes, list)
                else []
            )
            failure = OAuthTokenRequestError(response.status_code, error, codes)
            if prior:
                self.store.put(
                    self.record_id,
                    {
                        **prior,
                        "oauth_failure": {
                            "error": error,
                            "error_codes": codes,
                            "reauthorization_required": failure.reauthorization_required,
                        },
                    },
                )
            logger.warning("%s", failure)
            raise failure
        try:
            value = response.json()
        except ValueError as exc:
            raise RuntimeError("Microsoft OAuth token response is malformed") from exc
        if not isinstance(value, dict) or not isinstance(value.get("access_token"), str):
            raise RuntimeError("Microsoft OAuth token response is malformed")
        access_token = str(value["access_token"])
        if not access_token or len(access_token) > 65536:
            raise RuntimeError("Microsoft OAuth access token is malformed")
        token_type = str(value.get("token_type") or "Bearer")
        if token_type.casefold() != "bearer":
            raise RuntimeError("Microsoft OAuth token type is unsupported")
        try:
            expires_in = int(value.get("expires_in", 3600))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Microsoft OAuth token expiry is malformed") from exc
        if not 1 <= expires_in <= 86400:
            raise RuntimeError("Microsoft OAuth token expiry is outside the safety bound")
        granted_scope = str(value.get("scope") or " ".join(self.registration.scopes))
        granted = set(granted_scope.split())
        operational = {scope for scope in self.registration.scopes if scope != "offline_access"}
        if not operational <= granted:
            raise RuntimeError("Microsoft OAuth token is missing required mail scopes")
        refresh_token = value.get("refresh_token") or prior.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise RuntimeError("Microsoft OAuth response did not provide a refresh token")
        stored = {
            **{key: value for key, value in prior.items() if key != "oauth_failure"},
            "provider": "microsoft",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": (_now() + dt.timedelta(seconds=expires_in)).isoformat(timespec="seconds"),
            "scope": granted_scope,
            "token_type": "Bearer",
        }
        self.store.put(self.record_id, stored)
        logger.info("Microsoft OAuth credential refreshed record=%s", self.record_id)
        return stored
