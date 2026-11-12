from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import json
import logging
import re
import stat
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

import httpx
import jwt

from evergarden.auth.models import InvalidToken, Principal

logger = logging.getLogger(__name__)

# Ceilings applied to every compatibility registry. They are far above what the
# SOPS-provisioned inventory needs, and they bound what a self-service registry
# can grant even if its writer is compromised.
MAX_REGISTRY_ENTRIES = 32
MAX_REGISTRY_TTL_DAYS = 400
# JWKS fetching. A bearer token's kid is attacker-chosen before any signature is
# checked, so an unknown kid may trigger at most one fetch per refresh interval;
# otherwise it is rejected from the cached key set.
JWKS_TIMEOUT_SECONDS = 5.0
JWKS_REFRESH_INTERVAL_SECONDS = 60.0
JWKS_MAX_AGE_SECONDS = 300.0
JWKS_MAX_BYTES = 512 * 1024


class Verifier(Protocol):
    async def verify(self, token: str) -> Principal: ...


def _audiences(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise InvalidToken("token audience is missing or malformed")


def _principal_from_claims(claims: Mapping[str, Any], *, issuer: str) -> Principal:
    subject = str(claims.get("sub") or "")
    client_id = str(claims.get("client_id") or claims.get("azp") or "")
    if not subject or not client_id:
        raise InvalidToken("token subject/client is missing")
    scopes = claims.get("scope") or claims.get("scp") or ""
    if isinstance(scopes, list):
        scope_values = [str(value) for value in scopes]
    elif isinstance(scopes, str):
        scope_values = scopes.split()
    else:
        raise InvalidToken("token scope is malformed")
    return Principal.build(
        subject=subject,
        client_id=client_id,
        scopes=scope_values,
        audience=_audiences(claims.get("aud")),
        issuer=issuer,
    )


class JwksKeyCache:
    """Signing keys from a JWKS URL, fetched off the event loop and rate-limited.

    ``cached`` never performs I/O and is safe on the event loop. ``lookup`` may
    fetch, so callers run it in a worker thread. Fetches are serialised and at
    most one starts per ``refresh_interval``. Until the first fetch succeeds a
    lookup waits for a fetch in progress; afterwards a lookup that may not
    fetch, or that finds another fetch in progress, answers from the cache.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout: float = JWKS_TIMEOUT_SECONDS,
        refresh_interval: float = JWKS_REFRESH_INTERVAL_SECONDS,
        max_age: float = JWKS_MAX_AGE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        fetch: Callable[[], Mapping[str, Any]] | None = None,
    ):
        self.url = url
        self.timeout = timeout
        self.refresh_interval = refresh_interval
        self.max_age = max_age
        self._clock = clock
        self._fetch = fetch or self._fetch_http
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._lock = threading.Lock()
        self.fetches = 0

    def _fetch_http(self) -> Mapping[str, Any]:
        with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
            with client.stream("GET", self.url, headers={"Accept": "application/json"}) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > JWKS_MAX_BYTES:
                        raise ValueError("JWKS response is too large")
        return json.loads(bytes(body))

    def _fresh(self, now: float) -> bool:
        return self._fetched_at is not None and now - self._fetched_at < self.max_age

    def cached(self, kid: str) -> Any | None:
        """Return a fresh cached key, or None when a lookup is needed."""
        if self._fresh(self._clock()):
            return self._keys.get(kid)
        return None

    def needs_lookup(self, kid: str) -> bool:
        now = self._clock()
        if self._fresh(now) and kid in self._keys:
            return False
        # Before the first successful fetch a lookup waits for any fetch in
        # progress instead of rejecting a token it cannot judge yet.
        return self._fetched_at is None or self._may_fetch(now) or kid in self._keys

    def _may_fetch(self, now: float) -> bool:
        return self._attempted_at is None or now - self._attempted_at >= self.refresh_interval

    def lookup(self, kid: str) -> Any:
        now = self._clock()
        # Before the first successful fetch there is nothing to answer from, so
        # wait for a fetch in progress even when this lookup may not start one;
        # afterwards never queue behind a fetch and answer from the cache.
        waited = self._fetched_at is None
        if not (self._fresh(now) and kid in self._keys) and (waited or self._may_fetch(now)):
            if self._lock.acquire(blocking=waited, timeout=self.timeout + 1 if waited else -1):
                try:
                    if self._may_fetch(self._clock()):
                        self._refresh()
                finally:
                    self._lock.release()
        try:
            return self._keys[kid]
        except KeyError:
            raise InvalidToken("JWT signing key is unknown") from None

    def _refresh(self) -> None:
        self._attempted_at = self._clock()
        self.fetches += 1
        try:
            document = self._fetch()
            keys = {}
            for item in jwt.PyJWKSet.from_dict(dict(document)).keys:
                if item.key_id and item.public_key_use in {None, "sig"}:
                    keys[str(item.key_id)] = item.key
        except (httpx.HTTPError, jwt.PyJWTError, ValueError, TypeError) as exc:
            # Keep the previous keys: a JWKS outage must not reject valid tokens.
            logger.warning("JWKS refresh failed error_class=%s", type(exc).__name__)
            return
        self._keys = keys
        self._fetched_at = self._clock()


class JwtVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        resource: str,
        jwks_url: str | None = None,
        jwks: Mapping[str, Any] | None = None,
        algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA"),
        key_cache: JwksKeyCache | None = None,
    ):
        if not jwks_url and not jwks and key_cache is None:
            raise ValueError("jwks_url or static jwks is required")
        self.issuer = issuer.rstrip("/")
        self.resource = resource
        self.algorithms = algorithms
        self.keys = key_cache or (JwksKeyCache(jwks_url) if jwks_url else None)
        self.static_keys = {
            str(item["kid"]): jwt.PyJWK.from_dict(item).key
            for item in (jwks or {}).get("keys", [])
            if isinstance(item, dict) and item.get("kid")
        }

    async def _signing_key(self, kid: str) -> Any:
        if self.keys is None:
            return self.static_keys[kid]
        key = self.keys.cached(kid)
        if key is not None:
            return key
        if not self.keys.needs_lookup(kid):
            raise InvalidToken("JWT signing key is unknown")
        # A lookup may fetch the JWKS over the network: never on the event loop.
        return await asyncio.to_thread(self.keys.lookup, kid)

    async def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid or len(kid) > 256:
                raise InvalidToken("JWT key id is missing")
            key = await self._signing_key(kid)
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self.algorithms),
                audience=self.resource,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
            raise InvalidToken("JWT validation failed") from exc
        principal = _principal_from_claims(claims, issuer=self.issuer)
        if self.resource not in principal.audience:
            raise InvalidToken("token was issued for a different resource")
        return principal


class IntrospectionVerifier:
    def __init__(
        self,
        *,
        endpoint: str,
        client_id: str,
        client_secret: str,
        issuer: str,
        resource: str,
        http: httpx.AsyncClient | None = None,
    ):
        self.endpoint = endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.issuer = issuer.rstrip("/")
        self.resource = resource
        self.http = http or httpx.AsyncClient()

    async def verify(self, token: str) -> Principal:
        try:
            response = await self.http.post(
                self.endpoint,
                data={"token": token, "token_type_hint": "access_token"},
                auth=(self.client_id, self.client_secret),
                timeout=10,
            )
        except httpx.HTTPError as exc:
            raise InvalidToken("token introspection unavailable") from exc
        if response.status_code != 200:
            raise InvalidToken("token introspection rejected")
        try:
            value = response.json()
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidToken("token introspection response is malformed") from exc
        if not isinstance(value, dict) or value.get("active") is not True:
            raise InvalidToken("token is inactive")
        exp = value.get("exp")
        try:
            expired = exp is None or float(exp) <= dt.datetime.now(dt.UTC).timestamp()
        except (TypeError, ValueError) as exc:
            raise InvalidToken("token expiry is malformed") from exc
        if expired:
            raise InvalidToken("token is expired")
        if not value.get("iss") or str(value["iss"]).rstrip("/") != self.issuer:
            raise InvalidToken("token issuer does not match")
        principal = _principal_from_claims(value, issuer=self.issuer)
        if self.resource not in principal.audience:
            raise InvalidToken("token was issued for a different resource")
        return principal


class CompatibilityTokenVerifier:
    """Hash-only compatibility tokens for clients that cannot run OAuth."""

    def __init__(
        self,
        path: Path,
        *,
        resource: str,
        issuer: str,
        reload: bool = False,
        optional: bool = False,
    ):
        self.resource = resource
        self.issuer = issuer.rstrip("/")
        self.path = path
        self.reload = reload
        self.optional = optional
        self.signature = self._signature(path)
        if self.signature is None and not optional:
            raise ValueError("compatibility token registry is missing")
        if self.signature is None:
            self.entries = []
        elif optional:
            # Match _maybe_reload: a corrupted optional registry must not
            # abort app startup and take down every other auth path with it.
            try:
                self.entries = self._load(path)
            except (ValueError, OSError) as exc:
                self.entries = []
                logger.error(
                    "compatibility token registry load failed error_class=%s",
                    type(exc).__name__,
                )
        else:
            self.entries = self._load(path)

    @staticmethod
    def _signature(path: Path) -> tuple[int, int, int] | None:
        """Identify the current file revision without reading or trusting it."""
        try:
            info = path.stat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        return (info.st_ino, info.st_mtime_ns, info.st_size)

    def _maybe_reload(self) -> None:
        signature = self._signature(self.path)
        if signature == self.signature:
            return
        self.signature = signature
        if signature is None:
            self.entries = []
            return
        try:
            self.entries = self._load(self.path)
        except (ValueError, OSError) as exc:
            # Fail closed. Keeping the previous entries would let a corrupted
            # write resurrect a token the operator just revoked.
            self.entries = []
            logger.error(
                "compatibility token registry reload failed error_class=%s", type(exc).__name__
            )

    @staticmethod
    def _load(path: Path) -> list[dict[str, Any]]:
        if path.is_symlink():
            raise ValueError("compatibility token registry must not be a symlink")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("compatibility token registry must be mode 0600")
        if info.st_size > 1024 * 1024:
            raise ValueError("compatibility token registry exceeds 1 MiB")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("compatibility token registry is malformed") from exc
        entries = value.get("tokens") if isinstance(value, dict) else None
        if not isinstance(entries, list):
            raise ValueError("compatibility token registry is malformed")
        if len(entries) > MAX_REGISTRY_ENTRIES:
            raise ValueError("compatibility token registry holds too many entries")
        horizon = dt.datetime.now(dt.UTC) + dt.timedelta(days=MAX_REGISTRY_TTL_DAYS)
        validated: list[dict[str, Any]] = []
        hashes: set[str] = set()
        clients: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("compatibility token entry is malformed")
            digest = str(entry.get("sha256") or "")
            client_id = str(entry.get("client_id") or "")
            subject = str(entry.get("subject") or "")
            audiences = entry.get("audience")
            scopes = entry.get("scopes")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not client_id
                or not subject
                or not isinstance(audiences, list)
                or not audiences
                or not all(isinstance(item, str) and item for item in audiences)
                or not isinstance(scopes, list)
                or not all(isinstance(item, str) and item for item in scopes)
            ):
                raise ValueError("compatibility token entry is malformed")
            try:
                expires_at = dt.datetime.fromisoformat(
                    str(entry["expires_at"]).replace("Z", "+00:00")
                )
                if expires_at.tzinfo is None:
                    raise ValueError
            except (KeyError, ValueError) as exc:
                raise ValueError("compatibility token expiry is malformed") from exc
            if expires_at.astimezone(dt.UTC) > horizon:
                raise ValueError("compatibility token expiry exceeds the permitted horizon")
            if digest in hashes or client_id in clients:
                raise ValueError("compatibility token registry contains duplicate identities")
            hashes.add(digest)
            clients.add(client_id)
            validated.append(entry)
        return validated

    async def verify(self, token: str) -> Principal:
        if not 16 <= len(token) <= 4096:
            raise InvalidToken("compatibility token is invalid")
        if self.reload:
            self._maybe_reload()
        presented = hashlib.sha256(token.encode()).hexdigest()
        now = dt.datetime.now(dt.UTC)
        for entry in self.entries:
            expected = str(entry.get("sha256") or "")
            if not expected or not hmac.compare_digest(presented, expected):
                continue
            expires_at = dt.datetime.fromisoformat(str(entry["expires_at"]).replace("Z", "+00:00"))
            if expires_at.astimezone(dt.UTC) <= now:
                raise InvalidToken("compatibility token is expired")
            principal = Principal.build(
                subject=str(entry["subject"]),
                client_id=str(entry["client_id"]),
                scopes=entry.get("scopes", []),
                audience=entry.get("audience", []),
                issuer=self.issuer,
            )
            if self.resource not in principal.audience:
                raise InvalidToken("compatibility token has the wrong audience")
            return principal
        raise InvalidToken("compatibility token is invalid")


class CompositeVerifier:
    def __init__(self, verifiers: list[Verifier]):
        if not verifiers:
            raise ValueError("at least one token verifier is required")
        self.verifiers = verifiers

    async def verify(self, token: str) -> Principal:
        for verifier in self.verifiers:
            try:
                return await verifier.verify(token)
            except InvalidToken:
                continue
        raise InvalidToken("access token is invalid")
