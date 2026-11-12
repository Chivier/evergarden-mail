#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
from pathlib import Path

from evergarden.config import DEFAULT_HOST_ID, HOST_ID_PATTERN, NO_WRITER


def encrypt(
    target: Path,
    value: dict,
    *,
    sops_config: Path,
    age_recipient: str | None = None,
) -> None:
    if target.exists():
        raise RuntimeError(f"refusing to overwrite existing SOPS file: {target}")
    executable = shutil.which("sops")
    if not executable:
        raise RuntimeError("sops is required")
    command = [executable]
    if age_recipient is None:
        command.extend(("--config", str(sops_config)))
    else:
        command.extend(("--age", age_recipient))
    command.extend(
        [
            "--encrypt",
            "--input-type",
            "json",
            "--output-type",
            "yaml",
            "--filename-override",
            str(target),
            "/dev/stdin",
        ]
    )
    process = subprocess.run(  # noqa: S603 - resolved trusted operator binary
        command,
        input=json.dumps(value),
        text=True,
        capture_output=True,
        check=True,
    )
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(process.stdout)
        stream.flush()
        os.fsync(stream.fileno())


def age_recipient(key_file: Path) -> str:
    if key_file.is_symlink() or not key_file.is_file():
        raise RuntimeError("age key must be an existing regular file")
    info = key_file.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise RuntimeError("age key must be owner-only")
    executable = shutil.which("age-keygen")
    if executable is None:
        raise RuntimeError("age-keygen is required to derive a recovery recipient")
    process = subprocess.run(  # noqa: S603 - resolved age-keygen binary and fixed arguments
        [executable, "-y", str(key_file)],
        check=True,
        capture_output=True,
        text=True,
    )
    value = process.stdout.strip()
    if not re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", value):
        raise RuntimeError("age-keygen returned a malformed recipient")
    return value


def token() -> str:
    return secrets.token_urlsafe(48)


def encryption_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", type=Path, default=Path(".local/config"))
    parser.add_argument("--sops-config", type=Path)
    parser.add_argument(
        "--age-key",
        type=Path,
        help="encrypt a recovery candidate to the owner-only age identity instead of host rules",
    )
    parser.add_argument(
        "--host-id",
        default=DEFAULT_HOST_ID,
        help="stable deployment name bound into credential encryption (default: %(default)s)",
    )
    args = parser.parse_args()
    if not HOST_ID_PATTERN.fullmatch(args.host_id) or args.host_id == NO_WRITER:
        raise RuntimeError("host id must be 1-63 letters, digits, '.', '_' or '-'")
    config_dir = args.config_dir.resolve()
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_dir.chmod(0o700)
    if config_dir.parent.name == ".local":
        config_dir.parent.chmod(0o700)
    sops_config = args.sops_config.resolve() if args.sops_config else config_dir / ".sops.yaml"
    if not sops_config.is_file():
        raise RuntimeError("a private SOPS creation-rules file is required")
    recovery_recipient = age_recipient(args.age_key) if args.age_key else None
    encrypt(
        config_dir / "common.sops.yaml",
        {
            "schema_version": 1,
            "mcp_resource": "https://evergarden.example.invalid/mcp",
            "oauth_issuer": "https://auth.example.invalid",
            "microsoft_oauth_client_id": "replace-with-public-client-id",
            "microsoft_oauth_tenant": "common",
            "microsoft_oauth_redirect_uri": ("http://127.0.0.1:8788/oauth/callback/microsoft"),
            "accounts": [],
            "clients": {
                "agent": {
                    "scopes": [
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
                    ]
                },
                "claude": {"scopes": ["mail:metadata", "mail:read", "mail:draft"]},
                "codex": {"scopes": ["mail:metadata", "mail:read"]},
                "mail-ui": {
                    "scopes": [
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
                    ]
                },
            },
        },
        sops_config=sops_config,
        age_recipient=recovery_recipient,
    )
    encrypt(
        config_dir / "host.sops.yaml",
        {
            "schema_version": 1,
            "host_id": args.host_id,
            "credential_store_key": encryption_key(),
            "postgres_password": token(),
            "compatibility_tokens": {
                "agent": token(),
                "claude": token(),
                "codex": token(),
                "mail-ui": token(),
            },
            # Writes stay off until the operator flips this one switch.
            "side_effects_enabled": False,
            "trash_actions_enabled": False,
            "writer_epoch": 1,
        },
        sops_config=sops_config,
        age_recipient=recovery_recipient,
    )
    print("created encrypted common and host SOPS configuration; no plaintext was written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
