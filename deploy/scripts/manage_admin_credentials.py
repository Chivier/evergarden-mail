#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from pathlib import Path

# Runnable as a plain script from a clone (before `uv sync`): the admin
# session module needs only the standard library.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evergarden.auth.admin_session import (
    AdminAuthError,
    credential_document,
    validate_password,
    validate_username,
)

# Defaults added to runtime.env when a key is absent. Keys already present keep
# their value, so a loopback install keeps EVERGARDEN_ADMIN_SECURE_COOKIES=false.
ADMIN_RUNTIME_VALUES = {
    "EVERGARDEN_ADMIN_CREDENTIAL_FILE": "/run/secrets/admin_credentials.json",
    "EVERGARDEN_ADMIN_SESSION_KEY_FILE": "/run/secrets/admin_session_key",
    "EVERGARDEN_ADMIN_SESSION_TTL_SECONDS": "604800",
    "EVERGARDEN_ADMIN_LOGIN_MAX_FAILURES": "15",
    "EVERGARDEN_ADMIN_LOGIN_WINDOW_SECONDS": "900",
    "EVERGARDEN_ADMIN_SECURE_COOKIES": "true",
}
LEGACY_PROXY_KEYS = {
    "EVERGARDEN_REVERSE_PROXY_SECRET_FILE",
    "EVERGARDEN_APPROVAL_UI_APPROVER_GROUP",
    "EVERGARDEN_APPROVAL_UI_ADMIN_GROUP",
    "EVERGARDEN_MAIL_UI_USER_GROUP",
    "EVERGARDEN_MAIL_UI_ADMIN_GROUP",
    "EVERGARDEN_MAIL_UI_SECURE_COOKIES",
}


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("admin runtime directory must not be a symlink")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError("admin runtime path must be a directory")
    path.chmod(0o700)


def _atomic_private(path: Path, content: str) -> None:
    _private_directory(path.parent)
    if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.lstat().st_mode)):
        raise RuntimeError("admin runtime file must be regular and must not be a symlink")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _password(*, generate: bool) -> str:
    if generate:
        return secrets.token_urlsafe(24)
    first = getpass.getpass("New Evergarden admin password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise RuntimeError("password confirmation did not match")
    return validate_password(first)


def _update_runtime_env(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("runtime environment must be an existing regular file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 128 * 1024:
        raise RuntimeError("runtime environment must be a bounded mode-0600 file")
    retained: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#"):
            retained.append(line)
            continue
        key, separator, _value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in seen:
            raise RuntimeError("runtime environment contains a malformed or duplicate key")
        seen.add(key)
        if key not in LEGACY_PROXY_KEYS:
            retained.append(line)
    retained.extend(
        f"{key}={value}" for key, value in ADMIN_RUNTIME_VALUES.items() if key not in seen
    )
    _atomic_private(path, "\n".join(retained).rstrip() + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize or rotate private Evergarden administrator login files."
    )
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--generate-password", action="store_true")
    parser.add_argument(
        "--recovery-output",
        type=Path,
        help="mode-0600 one-time plaintext output; move it to a password manager then remove it",
    )
    parser.add_argument(
        "--rotate-session-key",
        action="store_true",
        help="invalidate every existing browser session",
    )
    parser.add_argument(
        "--update-runtime-env",
        action="store_true",
        help=(
            "atomically drop legacy proxy-auth settings from .local/run/runtime.env and add "
            "missing administrator settings; existing values are kept"
        ),
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    local_root = root / ".local"
    _private_directory(local_root)
    run_root = local_root / "run"
    credential_path = run_root / "admin_credentials.json"
    session_key_path = run_root / "admin_session_key"
    try:
        username = validate_username(args.username)
        password = _password(generate=args.generate_password)
        document = credential_document(username, password)
    except AdminAuthError as exc:
        raise SystemExit(f"administrator credential rejected: {exc}") from exc

    if not session_key_path.exists() or args.rotate_session_key:
        _atomic_private(session_key_path, secrets.token_urlsafe(32) + "\n")
    _atomic_private(
        credential_path,
        json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n",
    )
    if args.recovery_output:
        output = args.recovery_output
        if not output.is_absolute():
            output = root / output
        _atomic_private(output, f"username={username}\npassword={password}\n")
    if args.update_runtime_env:
        _update_runtime_env(run_root / "runtime.env")

    print(
        "administrator login files are ready; no secret value was printed. "
        "Restart the web services to apply: docker compose restart mail-ui approval-ui"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
