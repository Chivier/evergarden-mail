from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from deploy import setup as deploy_setup
from evergarden.auth.admin_session import AdminSessionAuth, read_admin_credential
from evergarden.auth.credential_store import read_key_file
from evergarden.auth.policy import supported_scopes
from evergarden.auth.verifier import CompatibilityTokenVerifier
from evergarden.config import DEFAULT_HOST_ID, Settings
from evergarden.mail.models import load_account_configs

ROOT = Path(__file__).resolve().parents[1]
SECRETS = (
    "postgres_password",
    "pgpass",
    "credential_store_key",
    "admin_session_key",
    "admin_credentials.json",
    "mail_ui_mcp_token",
    "compatibility_tokens.json",
)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "deployment"
    root.mkdir(parents=True)
    (root / "docker-compose.yaml").write_text("services: {}\n", encoding="utf-8")
    return root


def _run(root: Path, *extra: str, capsys: pytest.CaptureFixture[str] | None = None) -> str:
    code = deploy_setup.main(["--root", str(root), "--non-interactive", "--host-id", "box", *extra])
    assert code == 0
    return capsys.readouterr().out if capsys else ""


def _env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _settings(root: Path) -> Settings:
    """Load runtime.env as the containers would, with host paths for secrets."""
    env = _env(root / ".local" / "run" / "runtime.env")
    run = root / ".local" / "run"
    env["EVERGARDEN_ACCOUNT_CONFIG_FILE"] = str(run / "mail-config" / "mail_accounts.json")
    return Settings(
        **{key.removeprefix("EVERGARDEN_").lower(): value for key, value in env.items()}
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_fresh_setup_creates_a_complete_private_loopback_install(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    out = _run(root, capsys=capsys)
    run = root / ".local" / "run"

    for directory in (
        root / ".local",
        run,
        run / "mail-config",
        run / "mcp-api-keys",
        *(
            root / ".local" / "data" / name
            for name in ("archive", "secrets", "reports", "recovery")
        ),
    ):
        assert directory.is_dir()
        assert _mode(directory) == 0o700
    for name in SECRETS:
        assert _mode(run / name) == (0o640 if name == "postgres_password" else 0o600), name
    assert _mode(run / "runtime.env") == 0o600

    password = (run / "postgres_password").read_text().strip()
    assert (run / "pgpass").read_text() == f"postgres:5432:evergarden:evergarden:{password}\n"
    assert len(read_key_file(run / "credential_store_key")) == 32

    # The generated admin password is printed once and verifies.
    printed = [line.split(": ", 1)[1] for line in out.splitlines() if "password: " in line]
    assert len(printed) == 1
    credential = read_admin_credential(run / "admin_credentials.json")
    assert credential.username == "admin"
    auth = AdminSessionAuth(
        session_key_file=run / "admin_session_key", credential_file=run / "admin_credentials.json"
    )
    assert auth.verify_login("admin", printed[0]) == "admin"

    # The mail UI's own MCP grant matches its token and the loopback resource.
    resource = "http://127.0.0.1:8788/mcp"
    verifier = CompatibilityTokenVerifier(
        run / "compatibility_tokens.json", resource=resource, issuer="https://auth.example.invalid"
    )
    principal = asyncio.run(verifier.verify((run / "mail_ui_mcp_token").read_text().strip()))
    assert principal.client_id == "mail-ui"
    assert set(principal.scopes) == set(deploy_setup.MAIL_UI_SCOPES)

    assert load_account_configs(run / "mail-config" / "mail_accounts.json") == ()

    env = _env(run / "runtime.env")
    assert env["EVERGARDEN_HOST_ID"] == "box"
    assert env["EVERGARDEN_SIDE_EFFECTS_ENABLED"] == "false"
    assert env["EVERGARDEN_TRASH_ACTIONS_ENABLED"] == "false"
    assert env["EVERGARDEN_ADMIN_SECURE_COOKIES"] == "false"
    assert env["EVERGARDEN_MCP_RESOURCE"] == resource
    assert env["EVERGARDEN_MAIL_UI_APPROVAL_URL"] == "http://127.0.0.1:8788"
    assert env["EVERGARDEN_MAIL_UI_API_KEYS_ENABLED"] == "true"
    assert env["EVERGARDEN_MAIL_UI_ACCOUNT_ADMIN_ENABLED"] == "true"
    settings = _settings(root)
    assert settings.mode == "read-only"
    assert settings.mail_ui_enabled and settings.mail_ui_api_keys_enabled

    compose = _env(root / ".env")
    assert compose["EVERGARDEN_UID"] == str(os.getuid())
    assert compose["EVERGARDEN_GID"] == str(os.getgid())
    assert compose["COMPOSE_PROFILES"] == "scheduler"
    assert compose["EVERGARDEN_COMPOSE_PROJECT"] == "evergarden"
    assert compose["EVERGARDEN_HTTP_PORT"] == "8788"
    assert "Provider writes (send, move, mark) are OFF" in out


def test_setup_is_idempotent_and_never_overwrites_or_reprints(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    _run(root, capsys=capsys)
    run = root / ".local" / "run"
    before = {name: (run / name).read_bytes() for name in SECRETS}
    env_before = (run / "runtime.env").read_bytes()
    (root / ".env").write_text("EVERGARDEN_COMPOSE_PROJECT=mine\n", encoding="utf-8")

    out = _run(root, "--public-origin", "https://mail.example.com", capsys=capsys)

    assert "password:" not in out
    assert {name: (run / name).read_bytes() for name in SECRETS} == before
    assert (run / "runtime.env").read_bytes() == env_before
    assert (root / ".env").read_text() == "EVERGARDEN_COMPOSE_PROJECT=mine\n"
    assert "keeps origin http://127.0.0.1:8788" in out


def test_reverse_proxy_origin_enables_secure_cookies(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _run(root, "--public-origin", "https://mail.example.com/", "--no-scheduler")
    env = _env(root / ".local" / "run" / "runtime.env")
    assert env["EVERGARDEN_ADMIN_SECURE_COOKIES"] == "true"
    assert env["EVERGARDEN_MCP_RESOURCE"] == "https://mail.example.com/mcp"
    assert env["EVERGARDEN_MICROSOFT_OAUTH_REDIRECT_URI"] == (
        "https://mail.example.com/oauth/callback/microsoft"
    )
    assert _env(root / ".env")["COMPOSE_PROFILES"] == ""
    assert _settings(root).admin_secure_cookies is True


def test_fresh_setup_defaults_to_direct_client_addresses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    out = _run(root, capsys=capsys)
    compose = _env(root / ".env")
    assert compose["EVERGARDEN_GATEWAY_REAL_IP"] == "direct"
    assert "EVERGARDEN_GATEWAY_TRUSTED_PROXIES" not in compose
    assert "#EVERGARDEN_GATEWAY_TRUSTED_PROXIES=" in (root / ".env").read_text()
    assert "shares one login throttle bucket" not in out


def test_https_origin_left_in_direct_mode_gets_a_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    out = _run(root, "--public-origin", "https://mail.example.com", capsys=capsys)
    assert "shares one login throttle bucket" in out
    assert _env(root / ".env")["EVERGARDEN_GATEWAY_REAL_IP"] == "direct"


@pytest.mark.parametrize(
    ("arguments", "mode", "trusted"),
    [
        (["--real-ip", "proxy"], "proxy", None),
        (
            ["--real-ip", "cloudflare", "--trusted-proxies", "198.51.100.0/24 192.0.2.10, fd00::1"],
            "cloudflare",
            "198.51.100.0/24,192.0.2.10/32,fd00::1/128",
        ),
        (["--real-ip", "cloudflare", "--trusted-proxies", "none"], "cloudflare", "none"),
        (["--real-ip", "proxy", "--trusted-proxies", "192.0.2.77/24"], "proxy", "192.0.2.0/24"),
    ],
)
def test_real_ip_options_are_written_to_the_compose_env(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    mode: str,
    trusted: str | None,
) -> None:
    root = _root(tmp_path)
    out = _run(root, "--public-origin", "https://mail.example.com", *arguments, capsys=capsys)
    compose = _env(root / ".env")
    assert compose["EVERGARDEN_GATEWAY_REAL_IP"] == mode
    assert compose.get("EVERGARDEN_GATEWAY_TRUSTED_PROXIES") == trusted
    assert "shares one login throttle bucket" not in out


def test_real_ip_on_an_existing_env_is_reported_not_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    _run(root)
    before = (root / ".env").read_text()
    out = _run(root, "--real-ip", "cloudflare", capsys=capsys)
    assert (root / ".env").read_text() == before
    assert "set EVERGARDEN_GATEWAY_REAL_IP=cloudflare there yourself" in out


def test_loopback_origin_port_becomes_the_published_port(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _run(root, "--public-origin", "http://localhost:18788", "--mcp-port", "18420")
    compose = _env(root / ".env")
    assert compose["EVERGARDEN_HTTP_PORT"] == "18788"
    assert compose["EVERGARDEN_MCP_PORT"] == "18420"
    assert compose["EVERGARDEN_APPROVAL_PORT"] == "8421"
    env = _env(root / ".local" / "run" / "runtime.env")
    assert env["EVERGARDEN_MCP_RESOURCE"] == "http://localhost:18788/mcp"
    assert env["EVERGARDEN_ADMIN_SECURE_COOKIES"] == "false"


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--public-origin", "http://mail.example.com"], "must use https"),
        (["--public-origin", "https://mail.example.com/app"], "without a path"),
        (["--public-origin", "ftp://mail.example.com"], "scheme://host"),
        (["--public-origin", "http://127.0.0.1:1", "--http-port", "2"], "differ"),
        (["--http-port", "70000"], "1-65535"),
        (["--project", "Bad Name"], "project name"),
        (["--host-id", "none"], "host id"),
        (["--admin-user", "bad user"], "admin username"),
        (["--trusted-proxies", "10.0.0.0/8"], "needs --real-ip proxy"),
        (["--real-ip", "direct", "--trusted-proxies", "10.0.0.0/8"], "needs --real-ip proxy"),
        (["--real-ip", "proxy", "--trusted-proxies", "proxy.example.com"], "not an IP"),
        (["--real-ip", "proxy", "--trusted-proxies", "0.0.0.0/0"], "every address"),
        (["--real-ip", "proxy", "--trusted-proxies", "::/0"], "every address"),
        (["--real-ip", "proxy", "--trusted-proxies", " , "], "at least one"),
    ],
)
def test_setup_rejects_unsafe_or_malformed_options(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], arguments: list[str], message: str
) -> None:
    root = _root(tmp_path)
    assert deploy_setup.main(["--root", str(root), "--non-interactive", *arguments]) == 1
    assert message in capsys.readouterr().err


def test_setup_refuses_a_new_key_for_an_existing_credential_store(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    store = root / ".local" / "data" / "secrets" / "credentials.db"
    store.parent.mkdir(parents=True)
    store.write_bytes(b"")
    assert deploy_setup.main(["--root", str(root), "--non-interactive"]) == 1
    assert "restore the key from backup" in capsys.readouterr().err
    assert not (root / ".local" / "run" / "credential_store_key").exists()


def test_setup_refuses_half_a_mail_ui_grant_and_docker_created_directories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    run = root / ".local" / "run"
    run.mkdir(parents=True)
    (run / "mail_ui_mcp_token").write_text("x" * 40 + "\n")
    (run / "mail_ui_mcp_token").chmod(0o600)
    assert deploy_setup.main(["--root", str(root), "--non-interactive"]) == 1
    assert "matching pair" in capsys.readouterr().err

    other = _root(tmp_path / "second")
    (other / ".local" / "run" / "admin_session_key").mkdir(parents=True)
    assert deploy_setup.main(["--root", str(other), "--non-interactive"]) == 1
    assert "not a regular file" in capsys.readouterr().err


def test_setup_leaves_the_root_mode_alone_and_lists_the_mailbox_steps(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    root.chmod(0o775)
    out = _run(root, capsys=capsys)
    assert _mode(root) == 0o775
    assert _mode(root / ".local") == 0o700
    assert "evergarden-provider-credential set-password --account <alias>" in out
    assert "docker compose restart mcp approval-ui mail-ui" in out
    assert "--renew-mail-ui-grant" in out


def test_setup_explains_a_deployment_directory_owned_by_someone_else(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    (root / ".local" / "run").mkdir(parents=True)
    monkeypatch.setattr(deploy_setup.os, "getuid", lambda: os.stat(root).st_uid + 1)
    assert deploy_setup.main(["--root", str(root), "--non-interactive"]) == 1
    err = capsys.readouterr().err
    assert "not by you" in err and "chown" in err and "Traceback" not in err
    assert not (root / ".local" / "run" / "postgres_password").exists()


def test_setup_turns_an_os_error_into_a_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)

    def denied(_self: object) -> None:
        raise PermissionError(1, "Operation not permitted", str(root / ".local"))

    monkeypatch.setattr(deploy_setup.Setup, "directories", denied)
    assert deploy_setup.main(["--root", str(root), "--non-interactive"]) == 1
    assert "Operation not permitted" in capsys.readouterr().err


def test_renewing_the_mail_ui_grant_extends_only_its_expiry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    _run(root)
    registry = root / ".local" / "run" / "compatibility_tokens.json"
    document = json.loads(registry.read_text())
    document["tokens"][0]["expires_at"] = "2020-01-01T00:00:00+00:00"
    other = {**document["tokens"][0], "client_id": "other", "sha256": "0" * 64}
    document["tokens"].append(other)
    registry.write_text(json.dumps(document))
    capsys.readouterr()

    out = _run(root, capsys=capsys)
    assert "expires 2020-01-01T00:00:00+00:00" in out
    assert json.loads(registry.read_text()) == document

    out = _run(root, "--renew-mail-ui-grant", capsys=capsys)
    renewed = json.loads(registry.read_text())
    assert "renewed until" in out and "docker compose restart mcp" in out
    assert renewed["tokens"][1] == other
    assert renewed["tokens"][0]["expires_at"] > "2026-"
    assert {k: v for k, v in renewed["tokens"][0].items() if k != "expires_at"} == {
        k: v for k, v in document["tokens"][0].items() if k != "expires_at"
    }
    assert _mode(registry) == 0o600
    # The renewed registry still loads in the MCP verifier.
    CompatibilityTokenVerifier._load(registry)

    registry.write_text(json.dumps({"tokens": [other]}))
    assert (
        deploy_setup.main(["--root", str(root), "--non-interactive", "--renew-mail-ui-grant"]) == 1
    )
    assert "cannot renew" in capsys.readouterr().err


def test_setup_refuses_world_readable_secrets_and_missing_compose(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    run = root / ".local" / "run"
    run.mkdir(parents=True)
    (run / "postgres_password").write_text("pw\n")
    (run / "postgres_password").chmod(0o644)
    assert deploy_setup.main(["--root", str(root), "--non-interactive"]) == 1
    assert "readable by other users" in capsys.readouterr().err

    assert deploy_setup.main(["--root", str(tmp_path), "--non-interactive"]) == 1
    assert "does not contain docker-compose.yaml" in capsys.readouterr().err


def test_mismatched_pgpass_is_kept_with_a_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    run = root / ".local" / "run"
    run.mkdir(parents=True)
    (run / "pgpass").write_text("postgres:5432:evergarden:evergarden:other\n")
    (run / "pgpass").chmod(0o600)
    _run(root)
    assert "does not match" in capsys.readouterr().err
    assert (run / "pgpass").read_text().endswith(":other\n")


def test_write_new_never_replaces_a_file_or_symlink(tmp_path: Path) -> None:
    target = tmp_path / "secret"
    deploy_setup.write_new(target, "one\n")
    with pytest.raises(deploy_setup.SetupError, match="refusing to overwrite"):
        deploy_setup.write_new(target, "two\n")
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "missing")
    with pytest.raises(deploy_setup.SetupError, match="refusing to overwrite"):
        deploy_setup.write_new(link, "x\n")
    assert target.read_text() == "one\n"
    assert [path.name for path in tmp_path.iterdir() if path.name.startswith(".")] == []
    with pytest.raises(deploy_setup.SetupError, match="symlink"):
        deploy_setup.private_directory(link)


def test_default_host_id_is_neutral_and_matches_the_code_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: "owner-laptop.example.test")
    assert deploy_setup.DEFAULT_HOST_ID == DEFAULT_HOST_ID
    root = _root(tmp_path)
    assert deploy_setup.main(["--root", str(root), "--non-interactive"]) == 0
    runtime = (root / ".local/run/runtime.env").read_text(encoding="utf-8")
    assert _env(root / ".local/run/runtime.env")["EVERGARDEN_HOST_ID"] == DEFAULT_HOST_ID
    assert "owner-laptop" not in runtime
    assert _settings(root).host_id == DEFAULT_HOST_ID


def test_explicit_host_id_is_written(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _run(root)
    assert _env(root / ".local/run/runtime.env")["EVERGARDEN_HOST_ID"] == "box"


def test_render_env_fills_activates_and_appends_keys() -> None:
    template = "# comment\nA=1\n#B=\nC=3\n"
    assert deploy_setup.render_env(template, {"A": "x", "B": "y", "D": "z"}) == (
        "# comment\nA=x\nB=y\nC=3\n\nD=z\n"
    )


def test_interactive_prompts_only_fill_unset_choices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(["https://mail.example.com", "cloudflare", "operator"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    args = deploy_setup.parse_args([])
    deploy_setup.interactive(args)
    assert args.public_origin == "https://mail.example.com"
    assert args.real_ip == "cloudflare"
    assert args.admin_user == "operator"
    # An https origin behind a reverse proxy defaults to proxy mode.
    answers = iter(["", ""])
    args = deploy_setup.parse_args(["--public-origin", "https://a.example.com"])
    deploy_setup.interactive(args)
    assert args.public_origin == "https://a.example.com"
    assert args.real_ip == "proxy"
    assert args.admin_user == "admin"
    # A loopback origin is not asked about a proxy and stays direct.
    answers = iter(["", ""])
    args = deploy_setup.parse_args([])
    deploy_setup.interactive(args)
    assert args.public_origin is None
    assert args.real_ip is None
    # An explicit --real-ip is never asked again.
    answers = iter([""])
    args = deploy_setup.parse_args(
        ["--public-origin", "https://a.example.com", "--real-ip", "direct"]
    )
    deploy_setup.interactive(args)
    assert args.real_ip == "direct"
    answers = iter(["cloudfare"])
    args = deploy_setup.parse_args(["--public-origin", "https://a.example.com"])
    with pytest.raises(deploy_setup.SetupError, match="client-address mode"):
        deploy_setup.interactive(args)


def test_mail_ui_scopes_are_known_mcp_scopes() -> None:
    assert set(deploy_setup.MAIL_UI_SCOPES) <= set(supported_scopes())
    assert "mail:operations" not in deploy_setup.MAIL_UI_SCOPES


def test_setup_runs_with_the_standard_library_only(tmp_path: Path) -> None:
    """The quickstart runs setup before `uv sync`: no site-packages allowed."""
    root = _root(tmp_path)
    result = subprocess.run(  # noqa: S603 - the interpreter running this test
        [
            sys.executable,
            "-I",
            "-S",
            str(ROOT / "deploy" / "setup.py"),
            "--root",
            str(root),
            "--non-interactive",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "password: " in result.stdout
    assert json.loads((root / ".local" / "run" / "admin_credentials.json").read_text())


def test_shell_entry_point_forwards_arguments(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed repository script
        [str(ROOT / "deploy" / "setup"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--public-origin" in result.stdout
