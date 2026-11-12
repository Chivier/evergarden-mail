#!/usr/bin/env python3
"""Prepare an Authelia configuration for Evergarden MCP OAuth clients.

The command never prints the loaded configuration or generated signing key. It
writes a separate mode-0600 candidate so operators can validate it with the
running Authelia image before atomically replacing the active configuration.
"""

from __future__ import annotations

import argparse
import copy
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import yaml

MCP_SCOPES = (
    "mail:metadata",
    "mail:read",
    "mail:attachments",
    "mail:draft",
    "mail:sync",
    "mail:organize",
    "mail:send-approved",
    "mail:settings",
    "mail:verification",
    "mail:delete",
    "mail:operations",
)
LIFESPAN_NAME = "evergarden_mcp_agents"
CLIENT_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,99}")
KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,99}")
DURATION_PATTERN = re.compile(r"[1-9][0-9]*(?:ms|s|m|h|d|w|M|y)")


def _private_regular_file(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} must be an existing regular file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise RuntimeError(f"{label} must be mode 0600")


def _mapping(value: object, *, label: str) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a mapping")
    return value


def _client_id(value: str, *, label: str) -> str:
    if not CLIENT_ID_PATTERN.fullmatch(value):
        raise RuntimeError(f"{label} is malformed")
    return value


def _resource(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path != "/mcp"
    ):
        raise RuntimeError("MCP resource must be an HTTPS /mcp URL")
    return value


def _callback(value: str, *, client: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.port is None
        or parsed.port < 1024
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(f"{client} callback must be an exact loopback HTTP URL")
    if client == "Codex":
        valid_path = re.fullmatch(r"/callback/[A-Za-z0-9_-]+", parsed.path)
    else:
        valid_path = parsed.path == "/callback"
    if not valid_path:
        raise RuntimeError(f"{client} callback path is malformed")
    return value


def _new_rsa_private_key() -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise RuntimeError("openssl is required to rotate the OIDC signing key")
    process = subprocess.run(  # noqa: S603 - resolved binary and fixed arguments
        [executable, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"],
        check=True,
        capture_output=True,
        text=True,
    )
    key = process.stdout
    if (
        not key.startswith("-----BEGIN PRIVATE KEY-----\n")
        or not key.rstrip().endswith("-----END PRIVATE KEY-----")
        or len(key) < 3000
    ):
        raise RuntimeError("openssl returned a malformed private key")
    return key


def _mcp_client(
    *,
    client_id: str,
    client_name: str,
    redirect_uri: str,
    resource: str,
    consent_duration: str,
) -> dict:
    return {
        "client_id": client_id,
        "client_name": client_name,
        "client_secret": "",
        "public": True,
        "authorization_policy": "two_factor",
        "require_pkce": True,
        "pkce_challenge_method": "S256",
        "redirect_uris": [redirect_uri],
        "audience": [resource],
        "scopes": ["openid", "offline_access", *MCP_SCOPES],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "requested_audience_mode": "explicit",
        "consent_mode": "pre-configured",
        "pre_configured_consent_duration": consent_duration,
        "lifespan": LIFESPAN_NAME,
        "access_token_signed_response_alg": "RS256",
        "userinfo_signed_response_alg": "none",
        "token_endpoint_auth_method": "none",
    }


def configure(
    value: dict,
    *,
    resource: str,
    codex_client_id: str,
    codex_redirect_uri: str,
    claude_client_id: str,
    claude_redirect_uri: str,
    refresh_token_lifespan: str,
    signing_key: str | None = None,
    signing_key_id: str | None = None,
) -> dict:
    """Return a transformed copy while preserving unrelated Authelia settings."""

    if codex_client_id == claude_client_id:
        raise RuntimeError("Codex and Claude must use distinct OAuth client ids")
    resource = _resource(resource)
    codex_client_id = _client_id(codex_client_id, label="Codex client id")
    claude_client_id = _client_id(claude_client_id, label="Claude client id")
    codex_redirect_uri = _callback(codex_redirect_uri, client="Codex")
    claude_redirect_uri = _callback(claude_redirect_uri, client="Claude")
    if not DURATION_PATTERN.fullmatch(refresh_token_lifespan):
        raise RuntimeError("refresh-token lifespan is malformed")
    if (signing_key is None) != (signing_key_id is None):
        raise RuntimeError("signing key and key id must be supplied together")
    if signing_key_id is not None and not KEY_ID_PATTERN.fullmatch(signing_key_id):
        raise RuntimeError("signing key id is malformed")

    result = copy.deepcopy(_mapping(value, label="Authelia configuration"))
    identity_providers = _mapping(
        result.setdefault("identity_providers", {}), label="identity_providers"
    )
    oidc = _mapping(identity_providers.setdefault("oidc", {}), label="identity_providers.oidc")

    lifespans = _mapping(oidc.setdefault("lifespans", {}), label="OIDC lifespans")
    custom = _mapping(lifespans.setdefault("custom", {}), label="OIDC custom lifespans")
    custom[LIFESPAN_NAME] = {
        "access_token": "1h",
        "refresh_token": refresh_token_lifespan,
        "id_token": "1h",
        "authorize_code": "1m",
    }

    scopes = _mapping(oidc.setdefault("scopes", {}), label="OIDC scopes")
    for scope in MCP_SCOPES:
        scopes[scope] = {"claims": []}

    raw_clients = oidc.setdefault("clients", [])
    if not isinstance(raw_clients, list) or not all(isinstance(item, dict) for item in raw_clients):
        raise RuntimeError("OIDC clients must be a list of mappings")
    managed_ids = {codex_client_id, claude_client_id}
    clients = [item for item in raw_clients if item.get("client_id") not in managed_ids]
    clients.extend(
        (
            _mcp_client(
                client_id=codex_client_id,
                client_name="Evergarden MCP for Codex",
                redirect_uri=codex_redirect_uri,
                resource=resource,
                consent_duration=refresh_token_lifespan,
            ),
            _mcp_client(
                client_id=claude_client_id,
                client_name="Evergarden MCP for Claude Code",
                redirect_uri=claude_redirect_uri,
                resource=resource,
                consent_duration=refresh_token_lifespan,
            ),
        )
    )
    oidc["clients"] = clients

    if signing_key is not None:
        jwks = oidc.get("jwks")
        if not isinstance(jwks, list):
            raise RuntimeError("OIDC jwks must be a list before key rotation")
        signing_index = next(
            (
                index
                for index, item in enumerate(jwks)
                if isinstance(item, dict)
                and item.get("use", "sig") == "sig"
                and item.get("algorithm", "RS256") == "RS256"
            ),
            None,
        )
        if signing_index is None:
            raise RuntimeError("OIDC has no RS256 signing key to rotate")
        rotated = copy.deepcopy(jwks[signing_index])
        rotated["key_id"] = signing_key_id
        rotated["algorithm"] = "RS256"
        rotated["use"] = "sig"
        rotated["key"] = signing_key
        rotated.pop("certificate_chain", None)
        jwks[signing_index] = rotated

    return result


def _atomic_private(path: Path, content: str) -> None:
    if path.exists() and path.is_symlink():
        raise RuntimeError("candidate output must not be a symlink")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise RuntimeError("candidate parent must be an existing directory")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare a private Authelia candidate for Evergarden MCP OAuth"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--codex-client-id", default="codex-evergarden")
    parser.add_argument("--codex-redirect-uri", required=True)
    parser.add_argument("--claude-client-id", default="claude-code-evergarden")
    parser.add_argument("--claude-redirect-uri", required=True)
    parser.add_argument("--refresh-token-lifespan", default="30d")
    parser.add_argument("--rotate-signing-key", action="store_true")
    parser.add_argument("--signing-key-id")
    args = parser.parse_args()

    _private_regular_file(args.config, label="Authelia configuration")
    if args.config.resolve() == args.output.resolve():
        raise RuntimeError("candidate output must differ from the active configuration")
    if args.rotate_signing_key and not args.signing_key_id:
        raise RuntimeError("--rotate-signing-key requires --signing-key-id")
    if args.signing_key_id and not args.rotate_signing_key:
        raise RuntimeError("--signing-key-id requires --rotate-signing-key")

    try:
        loaded = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RuntimeError("Authelia configuration is malformed") from exc
    signing_key = _new_rsa_private_key() if args.rotate_signing_key else None
    result = configure(
        loaded,
        resource=args.resource,
        codex_client_id=args.codex_client_id,
        codex_redirect_uri=args.codex_redirect_uri,
        claude_client_id=args.claude_client_id,
        claude_redirect_uri=args.claude_redirect_uri,
        refresh_token_lifespan=args.refresh_token_lifespan,
        signing_key=signing_key,
        signing_key_id=args.signing_key_id,
    )
    serialized = yaml.safe_dump(result, sort_keys=False, allow_unicode=True)
    _atomic_private(args.output, serialized)
    rotation = " with a rotated signing key" if args.rotate_signing_key else ""
    print(
        f"prepared mode-0600 Authelia candidate for 2 Evergarden MCP clients{rotation}; "
        "no secret values were printed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
