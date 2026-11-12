"""Static checks of the deployment files a fresh clone runs with."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from evergarden.config import Settings

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or "/bin/bash"


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that also reads Compose's !reset merge tag."""


_ComposeLoader.add_constructor(
    "!reset", lambda loader, node: ("!reset", loader.construct_sequence(node))
)


COMPOSE = yaml.safe_load((ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))
PROXY = yaml.load(
    (ROOT / "compose.proxy.yaml").read_text(encoding="utf-8"),
    Loader=_ComposeLoader,  # noqa: S506 - a SafeLoader subclass
)
SERVICES = COMPOSE["services"]
APP_SERVICES = (
    "migrate",
    "mcp",
    "approval-ui",
    "mail-ui",
    "worker",
    "scheduler",
    "oauth-maintenance",
)
# runtime.env.example values that differ from the code default on purpose:
# container paths of mounted secrets and the switches a quickstart turns on.
DEPLOYMENT_VALUES = {
    "EVERGARDEN_ACCOUNT_CONFIG_FILE": "/run/mail-config/mail_accounts.json",
    "EVERGARDEN_COMPATIBILITY_TOKEN_FILE": "/run/secrets/compatibility_tokens.json",
    "EVERGARDEN_MCP_API_KEYS_FILE": "/run/mcp-api-keys/api_keys.json",
    "EVERGARDEN_ADMIN_CREDENTIAL_FILE": "/run/secrets/admin_credentials.json",
    "EVERGARDEN_ADMIN_SESSION_KEY_FILE": "/run/secrets/admin_session_key",
    "EVERGARDEN_MAIL_UI_MCP_TOKEN_FILE": "/run/secrets/mail_ui_mcp_token",
    "EVERGARDEN_MCP_RESOURCE": "http://127.0.0.1:8788/mcp",
    "EVERGARDEN_ADMIN_SECURE_COOKIES": "false",
    "EVERGARDEN_MAIL_UI_ENABLED": "true",
    "EVERGARDEN_APPROVAL_UI_ENABLED": "true",
    "EVERGARDEN_OAUTH_CALLBACK_ENABLED": "true",
    "EVERGARDEN_MAIL_UI_ACCOUNT_ADMIN_ENABLED": "true",
    "EVERGARDEN_MAIL_UI_API_KEYS_ENABLED": "true",
}


def _example_keys(path: Path) -> tuple[dict[str, str], set[str]]:
    """Active KEY=value lines and commented #KEY= lines of an example file."""
    active: dict[str, str] = {}
    commented: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if match := re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line):
            assert match.group(1) not in active, f"duplicate {match.group(1)}"
            active[match.group(1)] = match.group(2)
        elif match := re.fullmatch(r"#([A-Z][A-Z0-9_]*)=(.*)", line):
            commented.add(match.group(1))
    return active, commented


def _render(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return ""
    return str(value)


def test_runtime_env_example_documents_every_setting_with_correct_defaults() -> None:
    active, commented = _example_keys(ROOT / "runtime.env.example")
    documented = set(active) | commented
    for name, field in Settings.model_fields.items():
        key = f"EVERGARDEN_{name.upper()}"
        assert key in documented, f"{key} is missing from runtime.env.example"
        if key in active:
            expected = DEPLOYMENT_VALUES.get(key, _render(field.default))
            assert active[key] == expected, f"{key} differs from its documented default"
    unknown = {key.removeprefix("EVERGARDEN_").lower() for key in documented} - set(
        Settings.model_fields
    )
    assert not unknown, f"runtime.env.example names unknown settings: {sorted(unknown)}"
    # Secrets are always referenced by file path, never inlined.
    for key in documented:
        if re.search(r"SECRET|PASSWORD|TOKEN|KEY(?!S_ENABLED)", key):
            assert key.endswith(("_FILE", "_ENABLED")), key


def test_runtime_env_example_is_a_valid_safe_configuration() -> None:
    active, _ = _example_keys(ROOT / "runtime.env.example")
    settings = Settings(
        **{key.removeprefix("EVERGARDEN_").lower(): value for key, value in active.items()}
    )
    assert settings.mode == "read-only"
    assert settings.side_effects_enabled is False
    assert settings.trash_actions_enabled is False
    assert settings.auto_approve_kinds == frozenset()


def test_env_example_holds_only_compose_variables_used_by_the_compose_files() -> None:
    active, commented = _example_keys(ROOT / ".env.example")
    documented = set(active) | commented
    settings_keys = {f"EVERGARDEN_{name.upper()}" for name in Settings.model_fields}
    assert not documented & settings_keys, "application settings belong in runtime.env.example"
    sources = (ROOT / "docker-compose.yaml").read_text() + (ROOT / "compose.proxy.yaml").read_text()
    interpolated = set(re.findall(r"\$\{([A-Z0-9_]+)", sources))
    assert interpolated <= documented, sorted(interpolated - documented)
    assert documented - interpolated <= {"COMPOSE_PROFILES", "COMPOSE_FILE"}
    assert active["COMPOSE_PROFILES"] == "scheduler"


def test_examples_carry_no_owner_specific_values() -> None:
    for name in (
        ".env.example",
        "runtime.env.example",
        "docker-compose.yaml",
        "compose.proxy.yaml",
    ):
        text = (ROOT / name).read_text(encoding="utf-8").casefold()
        assert "shadow" not in text, name
        assert "/home/" not in text, name
        assert "production-images" not in text, name


def test_compose_names_derive_from_one_project_variable() -> None:
    project = "${EVERGARDEN_COMPOSE_PROJECT:-evergarden}"
    assert COMPOSE["name"] == project
    assert COMPOSE["volumes"]["postgres-data"]["name"] == f"{project}-postgres"
    assert COMPOSE["networks"]["internal"]["name"] == f"{project}-internal"
    assert COMPOSE["networks"]["internal"]["internal"] is True
    assert COMPOSE["networks"]["egress"]["name"] == f"{project}-egress"
    assert COMPOSE["networks"]["db"]["name"] == f"{project}-db"
    assert COMPOSE["networks"]["db"]["internal"] is True
    assert "proxy" not in COMPOSE["networks"], "the external proxy network is an overlay"
    for service in APP_SERVICES:
        assert SERVICES[service]["image"] == "${EVERGARDEN_IMAGE:-evergarden:local}", service
    autologin = SERVICES["mfa-autologin"]
    assert autologin["image"] == "${EVERGARDEN_AUTOLOGIN_IMAGE:-evergarden-autologin:local}"
    assert autologin["build"]["args"]["BASE_IMAGE"] == "${EVERGARDEN_IMAGE:-evergarden:local}"
    dockerfile = (ROOT / "deploy/autologin/Dockerfile").read_text()
    assert "ARG BASE_IMAGE=evergarden:local" in dockerfile


# Services that read EVERGARDEN_DATABASE_URL and mount pgpass. Everything else
# must not even be able to open a TCP connection to postgres.
DATABASE_SERVICES = {"migrate", "mcp", "approval-ui", "worker", "scheduler"}


def _networks(service: dict) -> set[str]:
    networks = service.get("networks", [])
    return set(networks)


def test_only_database_services_share_a_network_with_postgres() -> None:
    assert _networks(SERVICES["postgres"]) == {"db"}
    for name, service in SERVICES.items():
        if name == "postgres":
            continue
        uses_database = name in DATABASE_SERVICES
        assert ("db" in _networks(service)) is uses_database, name
        mounts_pgpass = any("pgpass" in volume for volume in service.get("volumes", []))
        assert mounts_pgpass is uses_database, name
    assert _networks(SERVICES["mail-ui"]) == {"internal"}
    assert _networks(SERVICES["gateway"]) == {"internal", "egress"}
    assert _networks(SERVICES["migrate"]) == {"db"}
    assert _networks(SERVICES["mfa-autologin"]) == {"egress"}


def test_compose_publishes_loopback_ports_with_overridable_defaults() -> None:
    assert SERVICES["gateway"]["ports"] == [
        "${EVERGARDEN_HTTP_BIND:-127.0.0.1}:${EVERGARDEN_HTTP_PORT:-8788}:8080"
    ]
    assert SERVICES["mcp"]["ports"] == [
        "${EVERGARDEN_MCP_BIND:-127.0.0.1}:${EVERGARDEN_MCP_PORT:-8420}:8000"
    ]
    assert SERVICES["approval-ui"]["ports"] == [
        "${EVERGARDEN_APPROVAL_BIND:-127.0.0.1}:${EVERGARDEN_APPROVAL_PORT:-8421}:8010"
    ]
    # Docker publishes no port for a container that is only on internal networks.
    assert "egress" in SERVICES["gateway"]["networks"]
    for name, service in SERVICES.items():
        if name not in {"gateway", "mcp", "approval-ui"}:
            assert "ports" not in service, name


def test_proxy_overlay_attaches_only_the_gateway_under_its_alias() -> None:
    assert set(PROXY["services"]) == {"gateway"}
    # Only the proxy network reaches the gateway, as proxy/cloudflare real-IP
    # modes require.
    assert PROXY["services"]["gateway"]["ports"] == ("!reset", [])
    assert PROXY["services"]["gateway"]["networks"]["proxy"]["aliases"] == ["evergarden-gateway"]
    assert PROXY["networks"]["proxy"] == {
        "external": True,
        "name": "${EVERGARDEN_PROXY_NETWORK:-proxy}",
    }


def test_migrations_run_before_database_services_but_not_before_the_worker() -> None:
    migrate = SERVICES["migrate"]
    assert migrate["command"] == ["python", "-m", "apps.worker.main", "migrate"]
    assert migrate["restart"] == "no"
    assert "profiles" not in migrate
    for service in ("mcp", "approval-ui", "scheduler"):
        assert SERVICES[service]["depends_on"]["migrate"] == {
            "condition": "service_completed_successfully"
        }, service
    # A host timer runs `compose run --rm worker ... due`; it must not re-run
    # or wait on migrations.
    assert set(SERVICES["worker"]["depends_on"]) == {"postgres"}
    assert SERVICES["worker"]["profiles"] == ["jobs"]


def test_scheduler_is_an_opt_in_profile_running_the_loop() -> None:
    scheduler = SERVICES["scheduler"]
    assert scheduler["profiles"] == ["scheduler"]
    assert scheduler["command"] == ["python", "-m", "deploy.scripts.scheduler"]
    assert scheduler["restart"] == "unless-stopped"
    assert scheduler["volumes"] == SERVICES["worker"]["volumes"]
    assert "scheduler-heartbeat" in json.dumps(scheduler["healthcheck"])


# A stand-in for an existing deployment's private image overlay: pinned images,
# no builds, and the proxy attachment that every one of its explicit
# `--env-file runtime.env -f docker-compose.yaml -f <overlay>` commands needs.
LEGACY_OVERLAY = """\
services:
  migrate: {image: "evergarden-pinned:1", build: !reset null}
  mcp: {image: "evergarden-pinned:1", build: !reset null}
  approval-ui: {image: "evergarden-pinned:1", build: !reset null}
  mail-ui: {image: "evergarden-pinned:1", build: !reset null}
  worker: {image: "evergarden-pinned:1", build: !reset null}
  gateway:
    ports: !reset []
    networks:
      proxy:
        aliases: [evergarden-gateway]
networks:
  proxy:
    external: true
    name: proxy
"""


def _legacy_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    run = root / ".local" / "run"
    run.mkdir(parents=True)
    for name in ("docker-compose.yaml", "compose.proxy.yaml"):
        shutil.copy2(ROOT / name, root / name)
    shutil.copytree(ROOT / "deploy/nginx/real-ip", root / "deploy/nginx/real-ip")
    (run / "runtime.env").write_text(
        "EVERGARDEN_COMPOSE_PROJECT=legacy-project\n", encoding="utf-8"
    )
    (run / "images.compose.yaml").write_text(LEGACY_OVERLAY, encoding="utf-8")
    return root


def _compose_config(root: Path, *args: str) -> dict:
    result = subprocess.run(  # noqa: S603 - resolved docker binary, fixed arguments
        [str(shutil.which("docker")), "compose", *args, "config", "--format", "json"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        env={
            key: value
            for key, value in {**os.environ, "COMPOSE_PROFILES": ""}.items()
            if key not in {"COMPOSE_FILE", "COMPOSE_PROJECT_NAME"}
        },
    )
    if result.returncode != 0 and "unknown flag" in result.stderr:
        pytest.skip("docker compose plugin is unavailable")
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _assert_legacy_names(rendered: dict) -> None:
    assert rendered["name"] == "legacy-project"
    assert rendered["volumes"]["postgres-data"]["name"] == "legacy-project-postgres"
    assert rendered["networks"]["internal"]["name"] == "legacy-project-internal"
    assert rendered["networks"]["egress"]["name"] == "legacy-project-egress"
    assert rendered["networks"]["db"]["name"] == "legacy-project-db"
    assert set(rendered["services"]["postgres"]["networks"]) == {"db"}
    assert set(rendered["services"]["mail-ui"]["networks"]) == {"internal"}
    assert "db" in rendered["services"]["migrate"]["networks"]
    assert rendered["networks"]["proxy"]["name"] == "proxy"
    gateway = rendered["services"]["gateway"]["networks"]
    assert set(gateway) == {"internal", "egress", "proxy"}
    assert gateway["proxy"]["aliases"] == ["evergarden-gateway"]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_existing_project_name_renders_the_existing_resource_names(tmp_path: Path) -> None:
    root = _legacy_root(tmp_path)
    rendered = _compose_config(
        root,
        "--env-file",
        ".local/run/runtime.env",
        "-f",
        "docker-compose.yaml",
        "-f",
        "compose.proxy.yaml",
    )
    _assert_legacy_names(rendered)
    assert "ports" not in rendered["services"]["gateway"]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_explicit_private_overlay_form_keeps_the_proxy_alias_and_pins(tmp_path: Path) -> None:
    root = _legacy_root(tmp_path)
    rendered = _compose_config(
        root,
        "--env-file",
        ".local/run/runtime.env",
        "-f",
        "docker-compose.yaml",
        "-f",
        ".local/run/images.compose.yaml",
    )
    _assert_legacy_names(rendered)
    assert "ports" not in rendered["services"]["gateway"]
    for name in ("migrate", "mcp", "approval-ui", "mail-ui"):
        service = rendered["services"][name]
        assert service["image"] == "evergarden-pinned:1", name
        assert "build" not in service, name


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_compose_refuses_to_start_before_setup(tmp_path: Path) -> None:
    root = tmp_path / "fresh"
    root.mkdir()
    shutil.copy2(ROOT / "docker-compose.yaml", root / "docker-compose.yaml")
    shutil.copytree(ROOT / "deploy/nginx/real-ip", root / "deploy/nginx/real-ip")
    result = subprocess.run(  # noqa: S603 - resolved docker binary, fixed arguments
        [str(shutil.which("docker")), "compose", "config", "--quiet", "postgres"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if "unknown flag" in result.stderr:
        pytest.skip("docker compose plugin is unavailable")
    assert result.returncode != 0
    assert "runtime.env" in result.stderr
    assert not (root / ".local").exists()


def test_systemd_units_are_root_neutral_templates() -> None:
    units = sorted((ROOT / "deploy/systemd").iterdir())
    assert {unit.name for unit in units} == {
        "evergarden-production-dispatch.service",
        "evergarden-production-dispatch.timer",
        "evergarden-dispatch-alarm.service",
    }
    for unit in units:
        text = unit.read_text(encoding="utf-8")
        assert "%h/service" not in text, unit.name
        assert ".local/run/production-images" not in text, unit.name
        assert "--env-file" not in text, unit.name
    service = (ROOT / "deploy/systemd/evergarden-production-dispatch.service").read_text()
    assert "WorkingDirectory=@EVERGARDEN_ROOT@" in service
    assert "docker compose run --rm worker python -m apps.worker.main due" in service


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
def test_timer_installer_renders_units_for_an_explicit_root(tmp_path: Path) -> None:
    root = tmp_path / "deploy root"
    units = tmp_path / "units"
    (root / "deploy").mkdir(parents=True)
    shutil.copytree(ROOT / "deploy" / "systemd", root / "deploy" / "systemd")
    (root / "docker-compose.yaml").write_text("services: {}\n")
    environment = {
        **os.environ,
        "SYSTEMD_USER_UNIT_DIR": str(units),
        "EVERGARDEN_SKIP_SYSTEMCTL": "1",
    }
    script = str(ROOT / "deploy/scripts/install_production_timer.sh")
    refused = subprocess.run(  # noqa: S603 - fixed repository script
        [BASH, script, "--root", str(root)], env=environment, capture_output=True, text=True
    )
    assert refused.returncode == 1
    assert "whitespace" in refused.stderr

    root = root.rename(tmp_path / "root")
    installed = subprocess.run(  # noqa: S603 - fixed repository script
        [BASH, script, f"--root={root}"], env=environment, capture_output=True, text=True
    )
    assert installed.returncode == 0, installed.stderr
    service = (units / "evergarden-production-dispatch.service").read_text()
    assert f"WorkingDirectory={root}\n" in service
    alarm = (units / "evergarden-dispatch-alarm.service").read_text()
    assert f"ExecStart={root}/deploy/scripts/record_dispatch_failure.sh" in alarm
    assert "@EVERGARDEN_ROOT@" not in service + alarm

    (units / "evergarden-production-dispatch.service").write_text("[Service]\n# owner copy\n")
    kept = subprocess.run(  # noqa: S603 - fixed repository script
        [BASH, script, "--root", str(root)], env=environment, capture_output=True, text=True
    )
    assert kept.returncode == 0
    assert "kept" in kept.stderr
    assert "owner copy" in (units / "evergarden-production-dispatch.service").read_text()
    forced = subprocess.run(  # noqa: S603 - fixed repository script
        [BASH, script, "--root", str(root), "--force"],
        env=environment,
        capture_output=True,
        text=True,
    )
    assert forced.returncode == 0
    assert "owner copy" not in (units / "evergarden-production-dispatch.service").read_text()
    missing = subprocess.run(  # noqa: S603 - fixed repository script
        [BASH, script, "--root", str(tmp_path)], env=environment, capture_output=True, text=True
    )
    assert missing.returncode == 1


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
def test_dispatch_alarm_defaults_to_the_checkout_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "deploy" / "scripts").mkdir(parents=True)
    script = root / "deploy" / "scripts" / "record_dispatch_failure.sh"
    shutil.copy2(ROOT / "deploy/scripts/record_dispatch_failure.sh", script)
    (root / ".local" / "data" / "reports").mkdir(parents=True)
    environment = {key: value for key, value in os.environ.items() if key != "EVERGARDEN_ROOT"}
    result = subprocess.run(  # noqa: S603 - fixed repository script copy
        [BASH, str(script)], env=environment, capture_output=True, text=True
    )
    # No failed report at all latches the alarm (exit 1) and logs the entry.
    assert result.returncode == 1
    log = root / ".local" / "data" / "reports" / "dispatch-failures.jsonl"
    assert json.loads(log.read_text())["latched"] is True


def test_gateway_error_bodies_are_english_json_with_reason_codes() -> None:
    gateway = (ROOT / "deploy/nginx/evergarden-gateway.conf").read_text(encoding="utf-8")
    assert not re.search(r"[一-鿿]", gateway)
    bodies = re.findall(r"return (\d{3}) '(\{.*\})';", gateway)
    assert {status for status, _ in bodies} >= {"503", "413"}
    for _status, body in bodies:
        assert json.loads(body)["reason_code"] in {"UPSTREAM_UNAVAILABLE", "REQUEST_TOO_LARGE"}


def test_gateway_replaces_client_forwarded_for_instead_of_appending() -> None:
    gateway = (ROOT / "deploy/nginx/evergarden-gateway.conf").read_text(encoding="utf-8")
    assert "$proxy_add_x_forwarded_for" not in gateway
    forwarded = re.findall(r"proxy_set_header\s+X-Forwarded-For\s+([^;]+);", gateway)
    # One shared conf for every mode: the upstream always gets the single
    # address the selected real-IP mode resolved (tests/test_gateway_real_ip.py).
    assert forwarded and set(forwarded) == {"$evergarden_client_ip"}
    assert "include /tmp/evergarden-gateway/real-ip.conf;" in gateway
    assert "real_ip_header" not in gateway and "set_real_ip_from" not in gateway


def test_reverse_proxy_examples_use_placeholder_domains_only() -> None:
    examples = sorted((ROOT / "deploy/reverse-proxy").iterdir())
    assert {path.name for path in examples} >= {
        "Caddyfile.example",
        "nginx.conf.example",
        "README.md",
    }
    allowed = {"127.0.0.1", "localhost", "evergarden-gateway"}
    for path in [*examples, ROOT / "deploy/nginx/npm-mail-host-advanced.conf.example"]:
        text = path.read_text(encoding="utf-8")
        hosts = set(re.findall(r"https?://([a-z0-9.-]+)", text))
        hosts |= set(re.findall(r"^\s*server_name\s+([^;]+);", text, flags=re.MULTILINE))
        hosts |= set(re.findall(r"^([a-z0-9.-]+\.[a-z]+) \{", text, flags=re.MULTILINE))
        for host in hosts:
            assert host in allowed or host.endswith("example.com"), f"{path.name}: {host}"
    caddy = (ROOT / "deploy/reverse-proxy/Caddyfile.example").read_text()
    nginx = (ROOT / "deploy/reverse-proxy/nginx.conf.example").read_text()
    assert "127.0.0.1:8788" in caddy and "127.0.0.1:8788" in nginx
    assert "proxy_buffering off" in nginx and "flush_interval -1" in caddy


def test_gitleaks_config_has_value_level_allowlists_only() -> None:
    text = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    assert "paths" not in text
    assert "useDefault = true" in text
    assert "8.30.1" in text
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "GITLEAKS_VERSION: 8.30.1" in workflow
    for line in workflow.splitlines():
        if "uses:" in line:
            assert re.search(r"@[0-9a-f]{40} # v\d", line), line


def test_entry_points_are_executable() -> None:
    for name in (
        "deploy/setup",
        "deploy/setup.py",
        "deploy/scripts/quickstart_smoke.sh",
        "deploy/scripts/install_production_timer.sh",
        "deploy/scripts/record_dispatch_failure.sh",
    ):
        assert os.access(ROOT / name, os.X_OK), name
