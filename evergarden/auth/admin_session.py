from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from evergarden.private_json import PrivateJsonError, PrivateJsonStore

SESSION_COOKIE = "evergarden_admin_session"
# With Secure cookies the __Host- prefix makes the browser refuse the cookie
# unless it is Secure, host-only and Path=/, so a sibling subdomain cannot plant
# or shadow it. Plain-HTTP loopback installs cannot use the prefix.
SECURE_SESSION_COOKIE = f"__Host-{SESSION_COOKIE}"
SESSION_VERSION = 1
DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_REVOCATION_BYTES = 64 * 1024
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class AdminAuthError(RuntimeError):
    """An administrator credential or session was absent or invalid."""


@dataclass(frozen=True)
class AdminCredential:
    username: str
    salt: bytes
    digest: bytes
    n: int
    r: int
    p: int


@dataclass(frozen=True)
class AdminSession:
    subject: str
    csrf: str
    issued_at: int
    expires_at: int


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str, *, label: str, maximum: int = 4096) -> bytes:
    if not value or len(value) > maximum or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise AdminAuthError(f"{label} is malformed")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AdminAuthError(f"{label} is malformed") from exc


def _private_bytes(path: Path, *, label: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise AdminAuthError(f"{label} is missing") from exc
    except OSError as exc:
        if path.is_symlink():
            raise AdminAuthError(f"{label} must not be a symlink") from exc
        raise AdminAuthError(f"{label} could not be opened safely") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise AdminAuthError(f"{label} must be a regular mode-0600 file")
        if not 1 <= info.st_size <= maximum:
            raise AdminAuthError(f"{label} size is outside the safety bound")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            value = handle.read(maximum + 1)
        if not 1 <= len(value) <= maximum:
            raise AdminAuthError(f"{label} size is outside the safety bound")
        return value
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def validate_username(value: str) -> str:
    if not USERNAME_PATTERN.fullmatch(value):
        raise AdminAuthError(
            "admin username must be 1-64 ASCII letters, digits, dots, dashes or underscores"
        )
    return value


def validate_password(value: str) -> str:
    if len(value) < 12 or len(value) > 1024 or "\0" in value:
        raise AdminAuthError("admin password must contain 12-1024 characters")
    return value


def derive_password(
    password: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    validate_password(password)
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )


def credential_document(username: str, password: str) -> dict[str, object]:
    username = validate_username(username)
    salt = secrets.token_bytes(16)
    digest = derive_password(password, salt)
    return {
        "version": 1,
        "username": username,
        "password": {
            "algorithm": "scrypt",
            "salt": _b64encode(salt),
            "digest": _b64encode(digest),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
        },
    }


def read_admin_credential(path: Path) -> AdminCredential:
    raw = _private_bytes(path, label="admin credential", maximum=16 * 1024)
    try:
        value = json.loads(raw)
        password = value["password"]
        if set(value) != {"version", "username", "password"} or set(password) != {
            "algorithm",
            "salt",
            "digest",
            "n",
            "r",
            "p",
        }:
            raise KeyError("unexpected credential fields")
        username = validate_username(value["username"])
        if value["version"] != 1 or password["algorithm"] != "scrypt":
            raise KeyError("unsupported credential version")
        n = password["n"]
        r = password["r"]
        p = password["p"]
        if any(isinstance(item, bool) or not isinstance(item, int) for item in (n, r, p)):
            raise KeyError("invalid scrypt parameters")
        if (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
            raise KeyError("unsupported scrypt parameters")
        salt = _b64decode(password["salt"], label="admin credential salt")
        digest = _b64decode(password["digest"], label="admin credential digest")
        if len(salt) != 16 or len(digest) != SCRYPT_DKLEN:
            raise KeyError("credential length")
    except (json.JSONDecodeError, KeyError, TypeError, AdminAuthError) as exc:
        raise AdminAuthError("admin credential is malformed") from exc
    return AdminCredential(username=username, salt=salt, digest=digest, n=n, r=r, p=p)


def read_session_key(path: Path) -> bytes:
    raw = _private_bytes(path, label="admin session key", maximum=4096).strip()
    try:
        value = _b64decode(raw.decode("ascii"), label="admin session key")
    except UnicodeDecodeError as exc:
        raise AdminAuthError("admin session key is malformed") from exc
    if len(value) != 32:
        raise AdminAuthError("admin session key must decode to 32 bytes")
    return value


def session_cookie_name(secure: bool) -> str:
    return SECURE_SESSION_COOKIE if secure else SESSION_COOKIE


class SessionRevocations:
    """Per-subject "not before" times that sign out every earlier session.

    Sessions are stateless signed cookies, so logout records the time here and
    every service that authenticates sessions rejects tokens issued at or before
    it. The document is tiny and replaced atomically; readers re-read it only
    when its inode, size or mtime changes. A missing file means no revocation;
    an unsafe or malformed one rejects every session (fail closed).
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._store = PrivateJsonStore(path, label="admin session revocations")
        self._signature: tuple[int, int, int] | None = None
        self._not_before: dict[str, int] = {}
        self._lock = threading.Lock()

    def _parse(self, value: dict) -> dict[str, int]:
        subjects = value.get("not_before")
        if value.get("version") != 1 or not isinstance(subjects, dict):
            raise AdminAuthError("admin session revocations are malformed")
        result = {}
        for subject, timestamp in subjects.items():
            if (
                not isinstance(subject, str)
                or not USERNAME_PATTERN.fullmatch(subject)
                or isinstance(timestamp, bool)
                or not isinstance(timestamp, int)
            ):
                raise AdminAuthError("admin session revocations are malformed")
            result[subject] = timestamp
        return result

    def _read(self) -> dict[str, int]:
        try:
            value = self._store.read_json(max_bytes=MAX_REVOCATION_BYTES, default={})
        except (PrivateJsonError, OSError) as exc:
            raise AdminAuthError("admin session revocations are unreadable") from exc
        return self._parse(value) if value else {}

    def not_before(self, subject: str) -> int | None:
        try:
            info = os.stat(self.path, follow_symlinks=False)
            signature = (info.st_ino, info.st_mtime_ns, info.st_size)
        except FileNotFoundError:
            signature = None
        except OSError as exc:
            raise AdminAuthError("admin session revocations are unreadable") from exc
        with self._lock:
            if signature != self._signature:
                self._not_before = self._read() if signature else {}
                self._signature = signature
            return self._not_before.get(subject)

    def revoke(self, subject: str, at: int) -> None:
        try:
            with self._store.lock():
                current = self._store.read_json(max_bytes=MAX_REVOCATION_BYTES, default={})
                subjects = self._parse(current) if current else {}
                # Sessions issued after an earlier logout in the same second
                # carry that logout's time + 1 (see issue), so cover them too.
                previous = subjects.get(subject)
                subjects[subject] = at if previous is None else max(at, previous + 1)
                self._store.write_json({"version": 1, "not_before": subjects})
        except (PrivateJsonError, OSError) as exc:
            raise AdminAuthError("admin session revocation could not be recorded") from exc


class AdminSessionAuth:
    def __init__(
        self,
        *,
        session_key_file: Path,
        credential_file: Path | None = None,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        revocation_file: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not 300 <= ttl_seconds <= MAX_SESSION_TTL_SECONDS:
            raise AdminAuthError("admin session lifetime must be between 5 minutes and 30 days")
        self._key = read_session_key(session_key_file)
        self._credential = read_admin_credential(credential_file) if credential_file else None
        self.ttl_seconds = ttl_seconds
        self.revocations = SessionRevocations(revocation_file) if revocation_file else None
        self._clock = clock

    def revoke(self, subject: str) -> None:
        """Sign out every session of ``subject`` issued up to now, on every service."""
        if self.revocations is None:
            raise AdminAuthError("session revocation is not configured on this service")
        self.revocations.revoke(validate_username(subject), int(self._clock()))

    def verify_login(self, username: str, password: str) -> str:
        if self._credential is None:
            raise AdminAuthError("password login is unavailable on this service")
        try:
            candidate = derive_password(
                password,
                self._credential.salt,
                n=self._credential.n,
                r=self._credential.r,
                p=self._credential.p,
            )
        except AdminAuthError:
            candidate = b"\0" * len(self._credential.digest)
        username_ok = hmac.compare_digest(
            username.encode("utf-8"), self._credential.username.encode()
        )
        password_ok = hmac.compare_digest(candidate, self._credential.digest)
        if not (username_ok and password_ok):
            raise AdminAuthError("invalid administrator credentials")
        return self._credential.username

    def issue(self, subject: str) -> tuple[str, AdminSession]:
        subject = validate_username(subject)
        now = int(self._clock())
        if self.revocations is not None:
            # A login in the same second as a logout must outlive that logout.
            not_before = self.revocations.not_before(subject)
            if not_before is not None and now <= not_before:
                now = not_before + 1
        session = AdminSession(
            subject=subject,
            csrf=secrets.token_urlsafe(32),
            issued_at=now,
            expires_at=now + self.ttl_seconds,
        )
        payload = {
            "v": SESSION_VERSION,
            "sub": session.subject,
            "csrf": session.csrf,
            "iat": session.issued_at,
            "exp": session.expires_at,
            "nonce": secrets.token_urlsafe(18),
        }
        encoded = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
        signature = _b64encode(hmac.digest(self._key, encoded.encode("ascii"), "sha256"))
        return f"{encoded}.{signature}", session

    def authenticate(self, token: str) -> AdminSession:
        if not token or len(token) > 2048 or token.count(".") != 1:
            raise AdminAuthError("administrator login is required")
        encoded, presented = token.split(".", 1)
        expected = hmac.digest(self._key, encoded.encode("ascii", errors="ignore"), "sha256")
        try:
            signature = _b64decode(presented, label="admin session signature")
        except AdminAuthError as exc:
            raise AdminAuthError("administrator login is required") from exc
        if not hmac.compare_digest(signature, expected):
            raise AdminAuthError("administrator login is required")
        try:
            payload = json.loads(_b64decode(encoded, label="admin session payload"))
            if set(payload) != {"v", "sub", "csrf", "iat", "exp", "nonce"}:
                raise KeyError("unexpected fields")
            if payload["v"] != SESSION_VERSION:
                raise KeyError("version")
            subject = validate_username(payload["sub"])
            csrf = payload["csrf"]
            issued_at = payload["iat"]
            expires_at = payload["exp"]
            if (
                not isinstance(csrf, str)
                or not 32 <= len(csrf) <= 128
                or not isinstance(issued_at, int)
                or not isinstance(expires_at, int)
                or expires_at - issued_at != self.ttl_seconds
            ):
                raise KeyError("session values")
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            KeyError,
            TypeError,
            AdminAuthError,
        ) as exc:
            raise AdminAuthError("administrator login is required") from exc
        now = int(self._clock())
        if issued_at > now + 60 or expires_at <= now:
            raise AdminAuthError("administrator session has expired")
        if self.revocations is not None:
            not_before = self.revocations.not_before(subject)
            if not_before is not None and issued_at <= not_before:
                raise AdminAuthError("administrator session was signed out")
        return AdminSession(
            subject=subject,
            csrf=csrf,
            issued_at=issued_at,
            expires_at=expires_at,
        )


class LoginThrottle:
    """Small in-process failed-login limiter for the single administrator surface."""

    # Bounds memory when many distinct keys fail (for example a caller
    # rotating source addresses). Keys are the client addresses the gateway
    # resolves (EVERGARDEN_GATEWAY_REAL_IP), IPv6 grouped per /64 by the mail
    # UI; in its direct mode behind a reverse proxy there is only one.
    MAX_KEYS = 4096

    def __init__(
        self,
        *,
        # When every remote client shares one bucket (direct gateway mode
        # behind a reverse proxy), 15 keeps a stray third party's typos from
        # locking the real administrator out while still stopping brute force.
        max_failures: int = 15,
        window_seconds: int = 15 * 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._clock = clock
        self._attempts: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _live(self, key: str, now: float) -> deque[float] | None:
        """Return the key's unexpired failures, dropping the entry once empty."""
        attempts = self._attempts.get(key)
        if attempts is None:
            return None
        while attempts and attempts[0] <= now - self.window_seconds:
            attempts.popleft()
        if not attempts:
            del self._attempts[key]
            return None
        return attempts

    def retry_after(self, key: str) -> int:
        now = self._clock()
        with self._lock:
            attempts = self._live(key, now)
            if attempts is None or len(attempts) < self.max_failures:
                return 0
            return max(1, int(attempts[0] + self.window_seconds - now))

    def failure(self, key: str) -> None:
        now = self._clock()
        with self._lock:
            attempts = self._live(key, now)
            if attempts is None:
                if len(self._attempts) >= self.MAX_KEYS:
                    for stale in list(self._attempts):
                        self._live(stale, now)
                while len(self._attempts) >= self.MAX_KEYS:
                    # Evict the key that started failing first.
                    del self._attempts[next(iter(self._attempts))]
                attempts = self._attempts[key] = deque()
            attempts.append(now)

    def success(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
