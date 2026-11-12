from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path

import pytest

from deploy.scripts import manage_admin_credentials as manage
from evergarden.auth.admin_session import AdminSessionAuth

ROOT = Path(__file__).resolve().parents[1]


def _runtime_env(root: Path, content: str) -> Path:
    path = root / ".local" / "run" / "runtime.env"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_generated_credentials_verify_and_recovery_file_is_private(tmp_path: Path) -> None:
    assert (
        manage.main(
            ["--root", str(tmp_path), "--generate-password", "--recovery-output", "recovery.txt"]
        )
        == 0
    )
    run = tmp_path / ".local" / "run"
    recovery = (tmp_path / "recovery.txt").read_text().splitlines()
    password = recovery[1].split("=", 1)[1]
    assert stat.S_IMODE((tmp_path / "recovery.txt").stat().st_mode) == 0o600
    auth = AdminSessionAuth(
        session_key_file=run / "admin_session_key", credential_file=run / "admin_credentials.json"
    )
    assert auth.verify_login("admin", password) == "admin"
    key = (run / "admin_session_key").read_bytes()
    assert manage.main(["--root", str(tmp_path), "--generate-password"]) == 0
    assert (run / "admin_session_key").read_bytes() == key
    assert (
        manage.main(["--root", str(tmp_path), "--generate-password", "--rotate-session-key"]) == 0
    )
    assert (run / "admin_session_key").read_bytes() != key


def test_update_runtime_env_keeps_existing_values_and_drops_legacy_proxy_keys(
    tmp_path: Path,
) -> None:
    path = _runtime_env(
        tmp_path,
        "# loopback install\n"
        "EVERGARDEN_ADMIN_SECURE_COOKIES=false\n"
        "EVERGARDEN_REVERSE_PROXY_SECRET_FILE=/run/secrets/proxy\n"
        "EVERGARDEN_HOST_ID=box\n",
    )
    assert (
        manage.main(["--root", str(tmp_path), "--generate-password", "--update-runtime-env"]) == 0
    )
    lines = path.read_text().splitlines()
    assert "EVERGARDEN_ADMIN_SECURE_COOKIES=false" in lines
    assert "EVERGARDEN_ADMIN_SECURE_COOKIES=true" not in lines
    assert "EVERGARDEN_HOST_ID=box" in lines
    assert "EVERGARDEN_ADMIN_LOGIN_MAX_FAILURES=15" in lines
    assert not any(line.startswith("EVERGARDEN_REVERSE_PROXY_SECRET_FILE") for line in lines)
    assert lines[0] == "# loopback install"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("EVERGARDEN_A=1\nEVERGARDEN_A=2\n", "malformed or duplicate"),
        ("lowercase=1\n", "malformed or duplicate"),
    ],
)
def test_update_runtime_env_rejects_malformed_files(
    tmp_path: Path, content: str, message: str
) -> None:
    _runtime_env(tmp_path, content)
    with pytest.raises(RuntimeError, match=message):
        manage.main(["--root", str(tmp_path), "--generate-password", "--update-runtime-env"])


def test_update_runtime_env_requires_an_existing_private_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="existing regular file"):
        manage.main(["--root", str(tmp_path), "--generate-password", "--update-runtime-env"])
    path = _runtime_env(tmp_path, "EVERGARDEN_HOST_ID=box\n")
    path.chmod(0o644)
    with pytest.raises(RuntimeError, match="mode-0600"):
        manage.main(["--root", str(tmp_path), "--generate-password", "--update-runtime-env"])


def test_interactive_password_must_match_and_be_long_enough(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers = iter(["first-password-1", "other-password-2"])
    monkeypatch.setattr(manage.getpass, "getpass", lambda _prompt: next(answers))
    with pytest.raises(RuntimeError, match="did not match"):
        manage.main(["--root", str(tmp_path)])
    answers = iter(["short", "short"])
    with pytest.raises(SystemExit, match="12-1024 characters"):
        manage.main(["--root", str(tmp_path)])
    with pytest.raises(SystemExit, match="admin username"):
        manage.main(["--root", str(tmp_path), "--username", "bad user", "--generate-password"])


def test_script_runs_without_installed_dependencies(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603 - the interpreter running this test
        [
            sys.executable,
            "-I",
            "-S",
            str(ROOT / "deploy" / "scripts" / "manage_admin_credentials.py"),
            "--root",
            str(tmp_path),
            "--generate-password",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "no secret value was printed" in result.stdout
