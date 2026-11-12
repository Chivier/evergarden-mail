"""The gateway's real-client-address modes (deploy/nginx/real-ip/).

The behaviour of the rendered nginx configuration against forged and proxied
headers is checked by deploy/scripts/gateway_realip_smoke.sh, which needs
Docker; these tests cover the entrypoint, the snippets, the Cloudflare range
generator and the compose wiring without network access.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REAL_IP = ROOT / "deploy" / "nginx" / "real-ip"
ENTRYPOINT = REAL_IP / "entrypoint.sh"
MODES = ("direct", "proxy", "cloudflare")
RUNTIME_DIR = "/tmp/evergarden-gateway"
DEFAULT_TRUSTED = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
]
SH = shutil.which("sh") or "/bin/sh"


def _load_updater():
    spec = importlib.util.spec_from_file_location(
        "update_cloudflare_ranges", ROOT / "deploy" / "scripts" / "update_cloudflare_ranges.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _render(
    tmp_path: Path, mode: str | None = None, trusted: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "EVERGARDEN_GATEWAY_RUNTIME_DIR": str(tmp_path / "runtime"),
    }
    if mode is not None:
        env["EVERGARDEN_GATEWAY_REAL_IP"] = mode
    if trusted is not None:
        env["EVERGARDEN_GATEWAY_TRUSTED_PROXIES"] = trusted
    return subprocess.run(  # noqa: S603 - fixed shell and script
        [SH, str(ENTRYPOINT)], env=env, capture_output=True, text=True, check=False
    )


def _trusted_lines(tmp_path: Path) -> list[str]:
    text = (tmp_path / "runtime" / "trusted-proxies.conf").read_text()
    return re.findall(r"^set_real_ip_from (\S+);$", text, flags=re.MULTILINE)


# --- entrypoint ---------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_entrypoint_selects_the_mode_snippet(tmp_path: Path, mode: str) -> None:
    result = _render(tmp_path, mode)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "runtime" / "real-ip.conf").read_text() == (
        f"include /etc/nginx/real-ip/{mode}.conf;\n"
    )
    assert f"client address mode {mode}" in result.stdout
    assert _trusted_lines(tmp_path) == DEFAULT_TRUSTED


def test_entrypoint_defaults_to_direct(tmp_path: Path) -> None:
    result = _render(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "direct.conf" in (tmp_path / "runtime" / "real-ip.conf").read_text()


def test_entrypoint_writes_the_configured_trusted_proxies(tmp_path: Path) -> None:
    result = _render(tmp_path, "cloudflare", " 192.0.2.0/24,192.0.2.10  2001:db8::/48,fd00::1 ")
    assert result.returncode == 0, result.stderr
    assert _trusted_lines(tmp_path) == ["192.0.2.0/24", "192.0.2.10", "2001:db8::/48", "fd00::1"]


def test_entrypoint_trusts_nothing_for_none(tmp_path: Path) -> None:
    result = _render(tmp_path, "cloudflare", "none")
    assert result.returncode == 0, result.stderr
    assert _trusted_lines(tmp_path) == []


@pytest.mark.parametrize(
    ("mode", "trusted", "message"),
    [
        ("cloudfare", None, "must be direct, proxy or cloudflare"),
        ("Direct", None, "must be direct, proxy or cloudflare"),
        ("../proxy", None, "must be direct, proxy or cloudflare"),
        ("proxy", "proxy.example.com", "not an address"),
        ("proxy", "abc", "not an address"),
        ("proxy", "1.2.3", "not an address"),
        ("proxy", "256.1.1.1", "not an address"),
        ("proxy", "192.0.2.0/33", "prefix length"),
        ("proxy", "0.0.0.0/0", "never trust every address"),
        ("proxy", "::/0", "never trust every address"),
        ("proxy", "192.0.2.0/", "prefix length"),
        ("proxy", "10.0.0.0/8/8", "not an address"),
        ("proxy", "2001:db8::zz", "not an address"),
        ("proxy", "10.0.0.*", "not an address"),
        ("proxy", ",", "lists no address"),
        ("proxy", "none,10.0.0.0/8", "cannot be combined"),
        # The list is validated in every mode, so a typo cannot hide until the
        # mode changes.
        ("direct", "proxy.example.com", "not an address"),
    ],
)
def test_entrypoint_refuses_invalid_settings(
    tmp_path: Path, mode: str, trusted: str | None, message: str
) -> None:
    result = _render(tmp_path, mode, trusted)
    assert result.returncode == 64
    assert message in result.stderr
    assert not (tmp_path / "runtime" / "real-ip.conf").exists()


def test_entrypoint_hands_over_to_the_image_entrypoint() -> None:
    script = ENTRYPOINT.read_text()
    assert script.startswith("#!/bin/sh\n")
    assert 'exec /docker-entrypoint.sh "$@"' in script
    assert f"runtime=${{EVERGARDEN_GATEWAY_RUNTIME_DIR:-{RUNTIME_DIR}}}" in script
    assert "snippets=/etc/nginx/real-ip\n" in script
    assert f'default_trusted="{" ".join(DEFAULT_TRUSTED)}"' in script


# --- snippets -----------------------------------------------------------------


def _directives(path: Path) -> str:
    return "\n".join(
        line for line in path.read_text().splitlines() if not line.lstrip().startswith("#")
    )


@pytest.mark.parametrize("mode", MODES)
def test_each_mode_has_a_snippet_and_a_compose_env_file(mode: str) -> None:
    snippet = _directives(REAL_IP / f"{mode}.conf")
    assert re.search(r"^map .* \$evergarden_client_ip \{", snippet, flags=re.MULTILINE)
    env = (REAL_IP / f"{mode}.env").read_text().splitlines()
    assert [line for line in env if not line.startswith("#")] == [
        f"EVERGARDEN_GATEWAY_REAL_IP={mode}"
    ]


def test_only_the_three_modes_exist() -> None:
    assert sorted(path.stem for path in REAL_IP.glob("*.env")) == sorted(MODES)


def test_direct_mode_reads_no_forwarding_header() -> None:
    snippet = _directives(REAL_IP / "direct.conf")
    assert "real_ip" not in snippet and "$http_" not in snippet
    assert "default $remote_addr;" in snippet


@pytest.mark.parametrize("mode", ["proxy", "cloudflare"])
def test_proxy_modes_resolve_x_forwarded_for_from_trusted_proxies(mode: str) -> None:
    snippet = _directives(REAL_IP / f"{mode}.conf")
    assert f"include {RUNTIME_DIR}/trusted-proxies.conf;" in snippet
    assert "real_ip_header X-Forwarded-For;" in snippet
    assert "real_ip_recursive on;" in snippet
    assert "set_real_ip_from" not in snippet


def test_only_cloudflare_mode_reads_cf_connecting_ip() -> None:
    assert "cf_connecting_ip" not in _directives(REAL_IP / "proxy.conf")
    snippet = _directives(REAL_IP / "cloudflare.conf")
    assert "include /etc/nginx/real-ip/cloudflare-ranges.conf;" in snippet
    # CF-Connecting-IP counts only from a Cloudflare hop and only when nginx
    # parses it as a single address; everything else keeps the hop.
    assert "geo $http_cf_connecting_ip $evergarden_cf_client_valid {" in snippet
    assert "240.0.0.0/4 0;" in snippet
    assert (
        'map "$evergarden_via_cloudflare:$evergarden_cf_client_valid:$http_cf_connecting_ip"'
        in snippet
    )
    assert '"~^1:1:(?<evergarden_cf_client>[0-9A-Fa-f.:]+)$" $evergarden_cf_client;' in snippet
    assert "default $remote_addr;" in snippet


def test_cloudflare_ranges_file_is_well_formed_and_dated() -> None:
    updater = _load_updater()
    document = (REAL_IP / "cloudflare-ranges.conf").read_text()
    match = re.search(r"^# Fetched: (\d{4}-\d{2}-\d{2})$", document, flags=re.MULTILINE)
    assert match is not None
    fetched = dt.date.fromisoformat(match.group(1))
    ranges = updater.ranges_in(document)
    ipv4 = [item for item in ranges if ipaddress.ip_network(item).version == 4]
    ipv6 = [item for item in ranges if ipaddress.ip_network(item).version == 6]
    assert ipv4 and ipv6 and ranges == ipv4 + ipv6
    # The file is exactly what the generator writes for these ranges.
    assert updater.render(ipv4, ipv6, fetched) == document
    for network in map(ipaddress.ip_network, ranges):
        assert network.is_global and network.prefixlen >= 8


# --- update_cloudflare_ranges.py ---------------------------------------------

IPV4 = "173.245.48.0/20\n103.21.244.0/22\n\n"
IPV6 = "2400:cb00::/32\n2606:4700::/32\n"


def test_parse_ranges_keeps_published_order_and_drops_duplicates() -> None:
    updater = _load_updater()
    assert updater.parse_ranges(IPV4 + "173.245.48.0/20\n", 4) == [
        "173.245.48.0/20",
        "103.21.244.0/22",
    ]
    assert updater.parse_ranges(IPV6, 6) == ["2400:cb00::/32", "2606:4700::/32"]


@pytest.mark.parametrize(
    ("text", "version", "message"),
    [
        ("<html>blocked</html>", 4, "not a CIDR"),
        ("173.245.48.1/20", 4, "not a CIDR"),
        ("2400:cb00::/32", 4, "not an IPv4"),
        ("0.0.0.0/0", 4, "implausibly large"),
        ("\n", 6, "empty"),
    ],
)
def test_parse_ranges_rejects_anything_unexpected(text: str, version: int, message: str) -> None:
    updater = _load_updater()
    with pytest.raises(updater.RangesError, match=message):
        updater.parse_ranges(text, version)


def test_update_script_writes_checks_and_keeps_an_unchanged_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    updater = _load_updater()
    (tmp_path / "v4").write_text(IPV4)
    (tmp_path / "v6").write_text(IPV6)
    output = tmp_path / "ranges.conf"
    files = ["--ipv4-file", str(tmp_path / "v4"), "--ipv6-file", str(tmp_path / "v6")]
    assert updater.main([*files, "--output", str(output), "--check"]) == 1
    assert updater.main([*files, "--output", str(output)]) == 0
    written = output.read_text()
    assert "173.245.48.0/20 1;\n103.21.244.0/22 1;\n2400:cb00::/32 1;\n" in written
    assert f"# Fetched: {dt.datetime.now(dt.UTC).date().isoformat()}" in written
    # Unchanged ranges leave the file (and its date) alone.
    output.write_text(written.replace("# Fetched: ", "# Fetched: kept "))
    assert updater.main([*files, "--output", str(output)]) == 0
    assert "kept" in output.read_text()
    assert updater.main([*files, "--output", str(output), "--check"]) == 0
    (tmp_path / "v4").write_text("not a range\n")
    assert updater.main([*files, "--output", str(output)]) == 2
    assert "not a CIDR" in capsys.readouterr().err


def test_update_script_fetches_only_the_published_https_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    updater = _load_updater()
    assert updater.SOURCES == {
        4: "https://www.cloudflare.com/ips-v4",
        6: "https://www.cloudflare.com/ips-v6",
    }
    seen = []
    monkeypatch.setattr(
        updater, "fetch", lambda url: seen.append(url) or (IPV4 if url.endswith("v4") else IPV6)
    )
    output = tmp_path / "ranges.conf"
    assert updater.main(["--output", str(output)]) == 0
    assert seen == [updater.SOURCES[4], updater.SOURCES[6]]


# --- compose wiring -----------------------------------------------------------

COMPOSE = yaml.safe_load((ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))
GATEWAY = COMPOSE["services"]["gateway"]


def test_compose_runs_the_gateway_through_the_real_ip_entrypoint() -> None:
    assert GATEWAY["entrypoint"] == ["/bin/sh", "/etc/nginx/real-ip/entrypoint.sh"]
    assert GATEWAY["command"] == ["nginx", "-g", "daemon off;"]
    assert GATEWAY["env_file"] == [
        "./deploy/nginx/real-ip/${EVERGARDEN_GATEWAY_REAL_IP:-direct}.env"
    ]
    assert GATEWAY["environment"] == {
        "EVERGARDEN_GATEWAY_TRUSTED_PROXIES": "${EVERGARDEN_GATEWAY_TRUSTED_PROXIES:-}"
    }
    assert "./deploy/nginx/real-ip:/etc/nginx/real-ip:ro" in GATEWAY["volumes"]
    # The rendered files land on the existing /tmp tmpfs of the read-only root.
    assert GATEWAY["read_only"] is True
    assert any(mount.startswith("/tmp:rw") for mount in GATEWAY["tmpfs"])


def _compose_render(tmp_path: Path, **variables: str) -> subprocess.CompletedProcess[str]:
    root = tmp_path / "root"
    (root / ".local" / "run").mkdir(parents=True)
    (root / ".local" / "run" / "runtime.env").write_text("")
    shutil.copy2(ROOT / "docker-compose.yaml", root / "docker-compose.yaml")
    shutil.copytree(REAL_IP, root / "deploy" / "nginx" / "real-ip")
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COMPOSE_", "EVERGARDEN_"))
    }
    result = subprocess.run(  # noqa: S603 - resolved docker binary, fixed arguments
        [
            str(shutil.which("docker")),
            "compose",
            "--env-file",
            "/dev/null",
            "config",
            "--format",
            "json",
            "gateway",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        env={**env, **variables},
    )
    if "unknown flag" in result.stderr or "is not a docker command" in result.stderr:
        pytest.skip("docker compose plugin is unavailable")
    return result


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
@pytest.mark.parametrize(
    ("variables", "mode", "trusted"),
    [
        ({}, "direct", ""),
        ({"EVERGARDEN_GATEWAY_REAL_IP": "proxy"}, "proxy", ""),
        (
            {
                "EVERGARDEN_GATEWAY_REAL_IP": "cloudflare",
                "EVERGARDEN_GATEWAY_TRUSTED_PROXIES": "192.0.2.0/24",
            },
            "cloudflare",
            "192.0.2.0/24",
        ),
    ],
)
def test_compose_renders_the_selected_mode(
    tmp_path: Path, variables: dict[str, str], mode: str, trusted: str
) -> None:
    result = _compose_render(tmp_path, **variables)
    assert result.returncode == 0, result.stderr
    environment = json.loads(result.stdout)["services"]["gateway"]["environment"]
    assert environment["EVERGARDEN_GATEWAY_REAL_IP"] == mode
    assert environment["EVERGARDEN_GATEWAY_TRUSTED_PROXIES"] == trusted


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_compose_render_fails_for_an_unknown_mode(tmp_path: Path) -> None:
    result = _compose_render(tmp_path, EVERGARDEN_GATEWAY_REAL_IP="cloudfare")
    assert result.returncode != 0
    assert "cloudfare.env" in result.stderr
