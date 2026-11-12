"""Unattended Microsoft device-code reauthorization with stored password and TOTP.

The administrator deliberately trades the second factor's separation for fewer
interactive logins: the password and TOTP seed live together in the encrypted
credential store. The policy here keeps that trade bounded. It only acts when
the refresh token is actually unusable, spaces attempts out, and stops for good
once Microsoft rejects the stored password so it cannot drive an account lockout.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime as dt
import hashlib
import hmac
import logging
import struct
import time
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from evergarden.audit.redaction import redact_error_detail
from evergarden.auth.credential_store import CredentialNotFound, CredentialStore
from evergarden.auth.oauth_coordinator import OAuthCoordinator
from evergarden.auth.provider_oauth import MicrosoftOAuthClient, _parse_expiry

logger = logging.getLogger(__name__)

RECORD_PREFIX = "mfa-autologin:"
TOTP_STEP_SECONDS = 30
# The first retry waits 30 minutes and doubles up to 12 hours. Three failures
# in a row disable the account until it is re-enrolled.
BASE_BACKOFF = dt.timedelta(minutes=30)
MAX_BACKOFF = dt.timedelta(hours=12)
MAX_CONSECUTIVE_FAILURES = 3
# oauth-maintenance may hold a 35-second poll claim on the same flow.
AUTHORIZATION_WAIT_SECONDS = 120


class AutoLoginError(RuntimeError):
    """The browser did not reach Microsoft's device sign-in confirmation."""


class AutoLoginRejected(AutoLoginError):
    """Microsoft rejected the stored password or TOTP seed; never retry blindly."""


def record_id(account: str) -> str:
    return RECORD_PREFIX + account


def normalize_totp_secret(value: str) -> str:
    """Accept a bare base32 seed or the otpauth:// URI behind an authenticator QR code."""
    value = value.strip()
    if value.lower().startswith("otpauth://"):
        uri = urllib.parse.urlparse(value)
        params = {key: items[0] for key, items in urllib.parse.parse_qs(uri.query).items()}
        if uri.netloc.lower() != "totp":
            raise ValueError("only time-based (totp) authenticator URIs are supported")
        if (
            params.get("algorithm", "SHA1").upper() != "SHA1"
            or params.get("digits", "6") != "6"
            or params.get("period", "30") != "30"
        ):
            raise ValueError("only SHA1, 6-digit, 30-second TOTP is supported")
        value = params.get("secret", "")
    secret = "".join(value.split()).upper().rstrip("=")
    try:
        decoded = base64.b32decode(secret + "=" * (-len(secret) % 8))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("TOTP secret is not valid base32") from exc
    if len(decoded) < 10:
        raise ValueError("TOTP secret is too short")
    return secret


def totp(secret: str, step: int, *, digits: int = 6) -> str:
    """RFC 6238 SHA-1 code for a 30-second time step, as Microsoft Authenticator uses."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


@dataclasses.dataclass(frozen=True)
class LoginCredentials:
    username: str
    password: str
    next_totp: Callable[[], str]


class BrowserLogin(Protocol):
    def __call__(
        self, *, verification_uri: str, user_code: str, credentials: LoginCredentials
    ) -> None: ...


class MicrosoftAutoLogin:
    def __init__(
        self,
        *,
        store: CredentialStore,
        clients: Mapping[str, MicrosoftOAuthClient],
        browser_login: BrowserLogin,
        now: Callable[[], dt.datetime] | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.store = store
        self.clients = dict(clients)
        self.browser_login = browser_login
        self.now = now or (lambda: dt.datetime.now(dt.UTC))
        self.clock = clock
        self.sleep = sleep
        self.coordinator = OAuthCoordinator(store=store, clients=self.clients, now=self.now)

    def enroll(self, account: str, *, username: str, password: str, totp_secret: str) -> None:
        if account not in self.clients:
            raise ValueError("auto-login is only available for Microsoft OAuth accounts")
        if "@" not in username or not password:
            raise ValueError("a Microsoft sign-in address and password are required")
        self.store.put(
            record_id(account),
            {
                "username": username,
                "password": password,
                "totp_secret": normalize_totp_secret(totp_secret),
                "enrolled_at": self.now().isoformat(timespec="seconds"),
                "consecutive_failures": 0,
            },
        )

    def forget(self, account: str) -> None:
        """Overwrite the stored password and seed; the store keeps no deleted plaintext."""
        self.store.put(
            record_id(account),
            {
                "forgotten_at": self.now().isoformat(timespec="seconds"),
                "disabled_reason": "credentials forgotten; enroll again to resume",
            },
        )

    def enable(self, account: str) -> None:
        """Resume after an automatic stop; forgotten credentials still need enrolling."""
        value = self.store.get(record_id(account))
        if value.get("forgotten_at") or not value.get("password"):
            raise AutoLoginError("credentials were forgotten; enroll again to resume")
        self._update(account, disabled_reason=None, consecutive_failures=0, last_error=None)

    def status(self, account: str) -> dict[str, Any]:
        try:
            value = self.store.get(record_id(account))
        except CredentialNotFound:
            return {"account": account, "enrolled": False}
        return {
            "account": account,
            "enrolled": True,
            "username": value.get("username"),
            "enrolled_at": value.get("enrolled_at"),
            "disabled_reason": value.get("disabled_reason"),
            "consecutive_failures": value.get("consecutive_failures", 0),
            "last_attempt_at": value.get("last_attempt_at"),
            "last_success_at": value.get("last_success_at"),
            "last_error": value.get("last_error"),
        }

    def _needs_authorization(self, account: str) -> bool:
        try:
            value = self.store.get(self.clients[account].record_id)
        except CredentialNotFound:
            return True
        failure = value.get("oauth_failure") or {}
        return not value.get("refresh_token") or bool(failure.get("reauthorization_required"))

    def _next_totp(self, account: str) -> Callable[[], str]:
        def next_code() -> str:
            value, version = self.store.get_with_version(record_id(account))
            step = int(self.clock()) // TOTP_STEP_SECONDS
            remaining = TOTP_STEP_SECONDS - int(self.clock()) % TOTP_STEP_SECONDS
            # Microsoft refuses a code it has already accepted, and a code that
            # expires in transit fails as a wrong code. Wait for a fresh window.
            if step <= int(value.get("last_totp_step", -1)) or remaining < 5:
                self.sleep(remaining + 1)
                step = int(self.clock()) // TOTP_STEP_SECONDS
            self.store.put_if_version(
                record_id(account),
                expected_version=version,
                value={**value, "last_totp_step": step},
            )
            return totp(str(value["totp_secret"]), step)

        return next_code

    def _due(self, value: dict[str, Any]) -> bool:
        failures = int(value.get("consecutive_failures", 0))
        last = _parse_expiry(value.get("last_attempt_at"))
        if last is None or failures == 0:
            return True
        backoff = min(BASE_BACKOFF * 2 ** (failures - 1), MAX_BACKOFF)
        return self.now() >= last + backoff

    def _update(self, account: str, **changes: Any) -> None:
        value, version = self.store.get_with_version(record_id(account))
        self.store.put_if_version(
            record_id(account), expected_version=version, value={**value, **changes}
        )

    def _wait_for_authorization(self, flow_id: str) -> str:
        deadline = self.clock() + AUTHORIZATION_WAIT_SECONDS
        status = "authorization_pending"
        while self.clock() < deadline:
            status = str(self.coordinator.poll_device(flow_id)["status"])
            if status not in {"authorization_pending", "slow_down"}:
                return status
            self.sleep(5)
        return status

    def step(self, account: str, *, force: bool = False) -> dict[str, Any]:
        try:
            enrolled = self.store.get(record_id(account))
        except CredentialNotFound:
            return {"account": account, "action": "not-enrolled"}
        if enrolled.get("disabled_reason"):
            return {"account": account, "action": "disabled", "reason": enrolled["disabled_reason"]}
        if not force and not self._needs_authorization(account):
            return {"account": account, "action": "healthy"}
        if not force and not self._due(enrolled):
            return {"account": account, "action": "backing-off"}
        failures = int(enrolled.get("consecutive_failures", 0))
        self._update(account, last_attempt_at=self.now().isoformat(timespec="seconds"))
        try:
            flow = self.coordinator.start(account)
            if flow.get("flow") != "device_code":
                raise AutoLoginError("auto-login requires the Microsoft device code flow")
            self.browser_login(
                verification_uri=str(flow["verification_uri"]),
                user_code=str(flow["user_code"]),
                credentials=LoginCredentials(
                    username=str(enrolled["username"]),
                    password=str(enrolled["password"]),
                    next_totp=self._next_totp(account),
                ),
            )
            status = self._wait_for_authorization(str(flow["flow_id"]))
            if status != "authorized" and not self._needs_authorization(account):
                status = "authorized"
            if status != "authorized":
                raise AutoLoginError(f"device authorization ended as {status}")
        except AutoLoginRejected as exc:
            detail = redact_error_detail(exc)
            self._update(
                account,
                consecutive_failures=failures + 1,
                last_error=detail,
                disabled_reason=f"Microsoft rejected stored credentials: {detail}",
            )
            logger.error("MFA auto-login disabled account=%s detail=%s", account, detail)
            return {"account": account, "action": "disabled", "reason": detail}
        except Exception as exc:
            detail = redact_error_detail(exc)
            changes: dict[str, Any] = {
                "consecutive_failures": failures + 1,
                "last_error": detail,
            }
            if failures + 1 >= MAX_CONSECUTIVE_FAILURES:
                changes["disabled_reason"] = f"{failures + 1} consecutive failures"
            self._update(account, **changes)
            logger.warning(
                "MFA auto-login failed account=%s attempt=%s error_class=%s detail=%s",
                account,
                failures + 1,
                type(exc).__name__,
                detail,
            )
            return {"account": account, "action": "failed", "error_class": type(exc).__name__}
        self._update(
            account,
            consecutive_failures=0,
            last_error=None,
            last_success_at=self.now().isoformat(timespec="seconds"),
        )
        logger.info("MFA auto-login reauthorized account=%s", account)
        return {"account": account, "action": "reauthorized"}
