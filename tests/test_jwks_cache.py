from __future__ import annotations

import asyncio
import datetime as dt
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from evergarden.auth.models import InvalidToken
from evergarden.auth.verifier import (
    JWKS_REFRESH_INTERVAL_SECONDS,
    JWKS_TIMEOUT_SECONDS,
    JwksKeyCache,
    JwtVerifier,
)

ISSUER = "https://auth.test"
RESOURCE = "https://mail.test/mcp"


def _key(kid: str):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return private, jwk


def _token(private, kid: str) -> str:
    now = dt.datetime.now(dt.UTC)
    claims = {
        "sub": "user-1",
        "client_id": "codex",
        "scope": "mail:read",
        "aud": RESOURCE,
        "iss": ISSUER,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(minutes=5)).timestamp()),
    }
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": kid})


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class CountingFetch:
    def __init__(self, *jwks: dict) -> None:
        self.documents = {"keys": list(jwks)}
        self.calls = 0
        self.fail = False

    def __call__(self) -> dict:
        self.calls += 1
        if self.fail:
            raise ValueError("JWKS endpoint unavailable")
        return self.documents


async def test_unknown_kids_trigger_at_most_one_fetch_per_interval() -> None:
    private, jwk = _key("key-1")
    clock = Clock()
    fetch = CountingFetch(jwk)
    cache = JwksKeyCache("https://auth.test/jwks.json", clock=clock, fetch=fetch)
    verifier = JwtVerifier(issuer=ISSUER, resource=RESOURCE, key_cache=cache)

    assert (await verifier.verify(_token(private, "key-1"))).client_id == "codex"
    assert fetch.calls == 1
    for index in range(20):
        with pytest.raises(InvalidToken):
            await verifier.verify(_token(private, f"forged-{index}"))
    assert fetch.calls == 1
    # A known kid keeps working throughout.
    assert (await verifier.verify(_token(private, "key-1"))).subject == "user-1"

    clock.now += JWKS_REFRESH_INTERVAL_SECONDS
    with pytest.raises(InvalidToken):
        await verifier.verify(_token(private, "forged-late"))
    assert fetch.calls == 2
    with pytest.raises(InvalidToken):
        await verifier.verify(_token(private, "forged-later"))
    assert fetch.calls == 2


async def test_rotated_key_is_picked_up_and_outage_keeps_the_cached_keys() -> None:
    old_private, old_jwk = _key("old")
    new_private, new_jwk = _key("new")
    clock = Clock()
    fetch = CountingFetch(old_jwk)
    cache = JwksKeyCache("https://auth.test/jwks.json", clock=clock, fetch=fetch)
    verifier = JwtVerifier(issuer=ISSUER, resource=RESOURCE, key_cache=cache)
    await verifier.verify(_token(old_private, "old"))

    fetch.documents = {"keys": [old_jwk, new_jwk]}
    clock.now += JWKS_REFRESH_INTERVAL_SECONDS
    await verifier.verify(_token(new_private, "new"))
    assert fetch.calls == 2

    # The cached set expires, the endpoint is down: cached keys stay usable.
    fetch.fail = True
    clock.now += 3600
    await verifier.verify(_token(old_private, "old"))
    assert fetch.calls == 3
    await verifier.verify(_token(new_private, "new"))
    assert fetch.calls == 3


def test_jwks_fetch_has_a_short_explicit_timeout() -> None:
    assert JWKS_TIMEOUT_SECONDS <= 5
    assert JwksKeyCache("https://auth.test/jwks.json").timeout == JWKS_TIMEOUT_SECONDS


class SlowJwks(BaseHTTPRequestHandler):
    delay = 0.4
    body = b""
    hits = 0

    def do_GET(self) -> None:
        type(self).hits += 1
        time.sleep(self.delay)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *_args) -> None:
        pass


async def test_unknown_kid_flood_neither_blocks_the_loop_nor_refetches() -> None:
    private, jwk = _key("key-1")
    SlowJwks.body = json.dumps({"keys": [jwk]}).encode()
    SlowJwks.hits = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowJwks)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        verifier = JwtVerifier(
            issuer=ISSUER,
            resource=RESOURCE,
            jwks_url=f"http://127.0.0.1:{server.server_address[1]}/jwks.json",
        )
        lags: list[float] = []
        stop = asyncio.Event()

        async def ticker() -> None:
            while not stop.is_set():
                started = time.monotonic()
                await asyncio.sleep(0.02)
                lags.append(time.monotonic() - started)

        tick = asyncio.create_task(ticker())
        await asyncio.sleep(0.05)

        async def attempt(kid: str) -> None:
            with pytest.raises(InvalidToken):
                await verifier.verify(_token(private, kid))

        await asyncio.gather(*(attempt(f"forged-{index}") for index in range(4)))
        for index in range(4):
            await attempt(f"forged-again-{index}")
        stop.set()
        await tick
    finally:
        server.shutdown()
        server.server_close()
    assert SlowJwks.hits == 1
    assert max(lags) < SlowJwks.delay / 2


async def test_valid_tokens_during_the_first_slow_fetch_all_verify() -> None:
    # Agents reconnect together after an MCP restart: tokens that arrive while
    # the first JWKS fetch is still running must wait for it, not be rejected.
    private, jwk = _key("key-1")
    SlowJwks.body = json.dumps({"keys": [jwk]}).encode()
    SlowJwks.hits = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowJwks)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        verifier = JwtVerifier(
            issuer=ISSUER,
            resource=RESOURCE,
            jwks_url=f"http://127.0.0.1:{server.server_address[1]}/jwks.json",
        )

        async def attempt(delay: float) -> str:
            await asyncio.sleep(delay)
            return (await verifier.verify(_token(private, "key-1"))).subject

        subjects = await asyncio.gather(*(attempt(index * 0.08) for index in range(4)))
    finally:
        server.shutdown()
        server.server_close()
    assert subjects == ["user-1"] * 4
    assert SlowJwks.hits == 1


def test_failed_first_fetch_rejects_without_refetching_until_the_interval() -> None:
    _private, jwk = _key("key-1")
    clock = Clock()
    fetch = CountingFetch(jwk)
    fetch.fail = True
    cache = JwksKeyCache("https://auth.test/jwks.json", clock=clock, fetch=fetch)

    for _ in range(3):
        assert cache.needs_lookup("key-1")
        with pytest.raises(InvalidToken):
            cache.lookup("key-1")
    assert fetch.calls == 1

    fetch.fail = False
    clock.now += JWKS_REFRESH_INTERVAL_SECONDS
    assert cache.lookup("key-1") is not None
    assert fetch.calls == 2
