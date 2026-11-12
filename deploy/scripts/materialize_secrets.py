#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from evergarden.auth.admin_session import read_admin_credential, read_session_key
from evergarden.auth.policy import supported_scopes
from evergarden.config import DEFAULT_HOST_ID, HOST_ID_PATTERN, NO_WRITER
from evergarden.mail.models import (
    AccountConfigError,
    account_config_payload,
    parse_account_config_payload,
)


def _private_regular(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} must be an existing regular file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise RuntimeError(f"{label} must be mode 0600")


def decrypt(path: Path, key_file: Path) -> dict:
    _private_regular(key_file, label="age key")
    _private_regular(path, label="SOPS input")
    executable = shutil.which("sops")
    if not executable:
        raise RuntimeError("sops is required")
    process = subprocess.run(  # noqa: S603 - resolved trusted operator binary
        [executable, "--decrypt", "--output-type", "json", str(path)],
        env={**os.environ, "SOPS_AGE_KEY_FILE": str(key_file)},
        text=True,
        capture_output=True,
        check=True,
    )
    value = json.loads(process.stdout)
    if not isinstance(value, dict):
        raise RuntimeError(f"decrypted config is not an object: {path}")
    return value


def atomic_private(path: Path, content: str, *, mode: int = 0o600) -> None:
    private_directory(path.parent)
    if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.lstat().st_mode)):
        raise RuntimeError("private runtime file must be regular and must not be a symlink")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("private runtime directory must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError("private runtime path must be a directory")
    path.chmod(0o700)


def _https_url(value: str, *, label: str, origin_only: bool = False) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (origin_only and parsed.path not in {"", "/"})
    ):
        suffix = " origin" if origin_only else " URL"
        raise RuntimeError(f"{label} must be a credential-free HTTPS{suffix}")
    return value.rstrip("/") if origin_only else value


def _host_control(host: dict) -> dict[str, object]:
    """Validate the writer fields of the private host document."""
    host_id = host.get("host_id", DEFAULT_HOST_ID)
    active_writer = host.get("active_writer", host_id)
    epoch = host.get("writer_epoch", 1)
    side_effects = host.get("side_effects_enabled", False)
    trash = host.get("trash_actions_enabled", False)
    if (
        not isinstance(host_id, str)
        or not HOST_ID_PATTERN.fullmatch(host_id)
        or host_id == NO_WRITER
        or not isinstance(active_writer, str)
        or not HOST_ID_PATTERN.fullmatch(active_writer)
        or isinstance(epoch, bool)
        or not isinstance(epoch, int)
        or epoch < 1
        or not isinstance(side_effects, bool)
        or not isinstance(trash, bool)
        or (side_effects and active_writer != host_id)
    ):
        raise RuntimeError("private host document writer control is invalid")
    return {
        "host_id": host_id,
        "active_writer": active_writer,
        "writer_epoch": epoch,
        "side_effects_enabled": side_effects,
        "trash_actions_enabled": trash,
    }


def _read_env(path: Path) -> dict[str, str]:
    """Parse an existing runtime.env without following symlinks."""
    if path.is_symlink() or not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value
    return values


def _preserved_env(path: Path, managed: set[str]) -> dict[str, str]:
    """Keep operator-added runtime.env lines that this generator does not manage."""
    return {key: value for key, value in _read_env(path).items() if key not in managed}


WRITER_CONTROL_ENV = {
    "EVERGARDEN_HOST_ID": "host_id",
    "EVERGARDEN_ACTIVE_WRITER": "active_writer",
    "EVERGARDEN_WRITER_EPOCH": "writer_epoch",
    "EVERGARDEN_SIDE_EFFECTS_ENABLED": "side_effects_enabled",
    "EVERGARDEN_TRASH_ACTIONS_ENABLED": "trash_actions_enabled",
}


def _writer_control_changes(path: Path, control: dict[str, object]) -> list[str]:
    """Name the writer-control keys whose existing runtime.env value would change."""
    existing = _read_env(path)
    changed = []
    for key, field in WRITER_CONTROL_ENV.items():
        if key not in existing:
            continue
        value = control[field]
        rendered = str(value).lower() if isinstance(value, bool) else str(value)
        if existing[key].strip().lower() != rendered.lower():
            changed.append(key)
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--age-key", type=Path, required=True)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument(
        "--public-origin",
        help="credential-free HTTPS origin used for the MCP and human web surfaces",
    )
    parser.add_argument("--oauth-issuer", help="credential-free HTTPS OAuth issuer URL")
    parser.add_argument("--oauth-jwks-url", help="credential-free HTTPS JWKS URL")
    parser.add_argument("--enable-human-web", action="store_true")
    parser.add_argument("--enable-account-admin", action="store_true")
    parser.add_argument("--enable-api-keys", action="store_true")
    parser.add_argument(
        "--host-document",
        default="host.sops.yaml",
        help="file name of the private host SOPS document inside the config directory",
    )
    parser.add_argument(
        "--allow-writer-control-change",
        action="store_true",
        help=(
            "allow the host document to change host id, writer, epoch, side-effect or "
            "trash settings already present in runtime.env"
        ),
    )
    args = parser.parse_args()
    if args.enable_account_admin and not args.enable_human_web:
        raise RuntimeError("account administration requires enabled human web surfaces")
    if args.enable_api_keys and not args.enable_human_web:
        raise RuntimeError("API key issuance requires enabled human web surfaces")
    public_origin = (
        _https_url(args.public_origin, label="public", origin_only=True)
        if args.public_origin
        else None
    )
    oauth_issuer_override = (
        _https_url(args.oauth_issuer, label="OAuth issuer") if args.oauth_issuer else None
    )
    oauth_jwks_url = (
        _https_url(args.oauth_jwks_url, label="OAuth JWKS") if args.oauth_jwks_url else ""
    )
    root = args.root.resolve()
    local_root = root / ".local"
    raw_config_dir = args.config_dir if args.config_dir else local_root / "config"
    if raw_config_dir.is_symlink():
        raise RuntimeError("private config directory must not be a symlink")
    config_dir = raw_config_dir.resolve()
    run_root = local_root / "run"
    data_root = local_root / "data"
    for private_path in (
        local_root,
        run_root,
        data_root,
        data_root / "archive",
        data_root / "secrets",
        data_root / "reports",
        data_root / "recovery",
    ):
        private_directory(private_path)
    if args.enable_human_web:
        read_admin_credential(run_root / "admin_credentials.json")
        read_session_key(run_root / "admin_session_key")
    common = decrypt(config_dir / "common.sops.yaml", args.age_key)
    if Path(args.host_document).name != args.host_document:
        raise RuntimeError("host document must be a file name inside the config directory")
    host = decrypt(config_dir / args.host_document, args.age_key)
    control = _host_control(host)
    runtime_env = run_root / "runtime.env"
    changes = _writer_control_changes(runtime_env, control)
    if changes and not args.allow_writer_control_change:
        # Refuse before writing anything: a silent flip of these keys would turn
        # writes or Trash off, or change the identity bound into encrypted data.
        raise RuntimeError(
            "host document would change existing runtime.env writer control "
            f"({', '.join(changes)}); update the host document or pass "
            "--allow-writer-control-change"
        )
    runtime_mode = (
        "production"
        if control["side_effects_enabled"] and control["active_writer"] == control["host_id"]
        else "read-only"
    )
    mcp_resource = f"{public_origin}/mcp" if public_origin else common["mcp_resource"]
    oauth_issuer = oauth_issuer_override or common["oauth_issuer"]
    microsoft_redirect_uri = (
        f"{public_origin}/oauth/callback/microsoft"
        if public_origin
        else common["microsoft_oauth_redirect_uri"]
    )
    expires = dt.datetime.now(dt.UTC) + dt.timedelta(days=45)
    scopes = common["clients"]
    raw_accounts = common.get("accounts")
    try:
        accounts = parse_account_config_payload(
            {"schema_version": 1, "accounts": raw_accounts}, include_disabled=True
        )
    except AccountConfigError as exc:
        raise RuntimeError("private common mail account inventory is invalid") from exc
    if not accounts:
        raise RuntimeError("private common configuration has no mail accounts")
    known_scopes = set(supported_scopes())
    if not isinstance(scopes, dict) or set(scopes) != set(host.get("compatibility_tokens", {})):
        raise RuntimeError("private MCP client inventory does not match token inventory")
    for client in scopes.values():
        requested = client.get("scopes") if isinstance(client, dict) else None
        if (
            not isinstance(requested, list)
            or not requested
            or any(not isinstance(scope, str) or scope not in known_scopes for scope in requested)
        ):
            raise RuntimeError("private MCP client scope inventory is invalid")
    registry = {"tokens": []}
    for client_id, token in host["compatibility_tokens"].items():
        registry["tokens"].append(
            {
                "sha256": hashlib.sha256(token.encode()).hexdigest(),
                "client_id": client_id,
                "subject": f"{runtime_mode}:{client_id}",
                "audience": [mcp_resource],
                "scopes": scopes[client_id]["scopes"],
                "expires_at": expires.isoformat(timespec="seconds"),
            }
        )
        atomic_private(run_root / "smoke" / f"{client_id}.token", token + "\n")
        if client_id == "mail-ui":
            atomic_private(run_root / "mail_ui_mcp_token", token + "\n")
    password = host["postgres_password"]
    # The official Postgres image runs as its own uid. Compose grants it the
    # host deployment group, so this one file is group-readable but never
    # world-readable. All other runtime secrets remain 0600.
    atomic_private(run_root / "postgres_password", password + "\n", mode=0o640)
    atomic_private(run_root / "pgpass", f"postgres:5432:evergarden:evergarden:{password}\n")
    atomic_private(run_root / "credential_store_key", host["credential_store_key"] + "\n")
    atomic_private(
        run_root / "compatibility_tokens.json", json.dumps(registry, separators=(",", ":"))
    )
    # The mail UI writes its self-service key registry here. Create the mount
    # point up front so Docker cannot materialize it as a root-owned directory
    # the unprivileged container is unable to write.
    private_directory(run_root / "mcp-api-keys")
    atomic_private(
        run_root / "mail-config" / "mail_accounts.json",
        json.dumps(
            account_config_payload(accounts),
            ensure_ascii=False,
            separators=(",", ":"),
        ),
    )
    env = {
        "EVERGARDEN_HOST_ID": str(control["host_id"]),
        "EVERGARDEN_ACTIVE_WRITER": str(control["active_writer"]),
        "EVERGARDEN_WRITER_EPOCH": str(control["writer_epoch"]),
        "EVERGARDEN_SIDE_EFFECTS_ENABLED": str(control["side_effects_enabled"]).lower(),
        "EVERGARDEN_TRASH_ACTIONS_ENABLED": str(control["trash_actions_enabled"]).lower(),
        "EVERGARDEN_DATABASE_URL": "postgresql://evergarden@postgres:5432/evergarden",
        "EVERGARDEN_ARCHIVE_DIR": "/data/archive",
        "EVERGARDEN_REPORT_DIR": "/data/reports",
        "EVERGARDEN_CREDENTIAL_DB": "/data/secrets/credentials.db",
        "EVERGARDEN_CREDENTIAL_KEY_FILE": "/run/secrets/credential_store_key",
        "EVERGARDEN_ACCOUNT_CONFIG_FILE": "/run/mail-config/mail_accounts.json",
        "EVERGARDEN_MCP_RESOURCE": mcp_resource,
        "EVERGARDEN_OAUTH_ISSUER": oauth_issuer,
        "EVERGARDEN_OAUTH_JWKS_URL": oauth_jwks_url,
        "EVERGARDEN_COMPATIBILITY_TOKEN_FILE": "/run/secrets/compatibility_tokens.json",
        "EVERGARDEN_MCP_API_KEYS_FILE": "/run/mcp-api-keys/api_keys.json",
        "EVERGARDEN_MICROSOFT_OAUTH_CLIENT_ID": common["microsoft_oauth_client_id"],
        "EVERGARDEN_MICROSOFT_OAUTH_TENANT": common.get("microsoft_oauth_tenant", "common"),
        "EVERGARDEN_MICROSOFT_OAUTH_REDIRECT_URI": microsoft_redirect_uri,
        "EVERGARDEN_GOOGLE_OAUTH_REDIRECT_URI": (
            f"{public_origin}/oauth/callback/google"
            if public_origin
            else common.get(
                "google_oauth_redirect_uri", "http://127.0.0.1:8788/oauth/callback/google"
            )
        ),
        "EVERGARDEN_ADMIN_CREDENTIAL_FILE": "/run/secrets/admin_credentials.json",
        "EVERGARDEN_ADMIN_SESSION_KEY_FILE": "/run/secrets/admin_session_key",
        "EVERGARDEN_ADMIN_SESSION_TTL_SECONDS": "604800",
        "EVERGARDEN_ADMIN_LOGIN_MAX_FAILURES": "5",
        "EVERGARDEN_ADMIN_LOGIN_WINDOW_SECONDS": "900",
        "EVERGARDEN_ADMIN_SECURE_COOKIES": str(args.enable_human_web).lower(),
        "EVERGARDEN_APPROVAL_UI_ENABLED": str(args.enable_human_web).lower(),
        "EVERGARDEN_OAUTH_CALLBACK_ENABLED": str(args.enable_human_web).lower(),
        "EVERGARDEN_MAIL_UI_ENABLED": str(args.enable_human_web).lower(),
        "EVERGARDEN_MAIL_UI_MCP_URL": "http://mcp:8000/mcp",
        "EVERGARDEN_MAIL_UI_MCP_TOKEN_FILE": "/run/secrets/mail_ui_mcp_token",
        "EVERGARDEN_MAIL_UI_APPROVAL_URL": public_origin or "http://127.0.0.1:8788",
        "EVERGARDEN_MAIL_UI_ACCOUNT_ADMIN_ENABLED": str(args.enable_account_admin).lower(),
        "EVERGARDEN_MAIL_UI_API_KEYS_ENABLED": str(args.enable_api_keys).lower(),
        "EVERGARDEN_LOG_LEVEL": "INFO",
    }
    # The retired mode switch is derived from the side-effect setting now.
    preserved = _preserved_env(runtime_env, set(env) | {"EVERGARDEN_MODE"})
    atomic_private(
        runtime_env,
        "".join(f"{key}={value}\n" for key, value in {**env, **preserved}.items()),
    )
    print(
        f"materialized private {runtime_mode} runtime secrets for host "
        f"{control['host_id']}; kept {len(preserved)} operator-added settings; "
        "values were not printed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
