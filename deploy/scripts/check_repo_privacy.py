#!/usr/bin/env python3
"""Fail closed when the repository tree contains private runtime material or PII.

Two kinds of rules run over every file Git would publish (tracked plus
unignored files):

Generic rules, committed here, that catch the usual leaks of a self-hosted
project without naming anybody:

- runtime state paths (``.local/``, ``.env``, SOPS documents, databases, keys,
  mail files);
- dated notes such as ``docs/incident-2026-01-02.md`` (operational logs, not
  documentation);
- absolute home-directory paths (``/home/<user>``, ``/Users/<user>``);
- email addresses outside the reserved example domains;
- IPv4 addresses other than loopback, unspecified and documentation ranges,
  the generic private and reserved blocks written as whole networks (for
  example ``10.0.0.0/8``, but not a host or subnet inside one), and Cloudflare's
  published edge ranges (read from ``deploy/nginx/real-ip/cloudflare-ranges.conf``);
- 24-hex-digit identifiers in Markdown (dashboard, ray and object ids).

Private rules: an optional list of literals (or ``re:`` regular expressions),
one per line, that name the operator's own hosts, domains or accounts. The
list is loaded from ``--patterns PATH`` or ``EVERGARDEN_PRIVACY_PATTERNS`` and
must live outside the published tree (outside the repository, or in an ignored
path such as ``.local/``); ``.local/privacy-patterns`` is used when present.
The list itself is never committed.

Findings are reported only as file/line/reason, never the matched value, so
the scanner cannot echo a private value into CI logs. ``--history`` also scans
every reachable blob (or, during pre-push, exactly the pushed range).
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCAL_ROOT = ROOT / ".local"
DEFAULT_PATTERNS = LOCAL_ROOT / "privacy-patterns"
PATTERNS_ENV = "EVERGARDEN_PRIVACY_PATTERNS"
MAX_TEXT_BYTES = 5 * 1024 * 1024
EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})(?![\w.-])", re.I)
HOME_RE = re.compile(r"/(?:" + "Users" + r"|" + "home" + r")/([^/\s\"'<>]+)")
# Placeholder home directories that name nobody.
NEUTRAL_HOME_USERS = frozenset({"evergarden", "user", "username", "you", "runner", "example"})
IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w]|\.\d)")
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8")
)
# Whole generic blocks, as in trusted-proxy defaults; a host or subnet inside
# them still names somebody's network and is flagged.
GENERIC_NETWORKS = frozenset(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "240.0.0.0/4")
)
CIDR_SUFFIX_RE = re.compile(r"/(\d{1,2})(?!\d)")
CLOUDFLARE_RANGES = ROOT / "deploy" / "nginx" / "real-ip" / "cloudflare-ranges.conf"
HEX_ID_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{24}(?![0-9A-Za-z])")
DATED_DOC_RE = re.compile(r"(?:^|/)docs/(?:[^/]+/)*[^/]*20\d\d-[^/]*\.md$", re.I)
RESERVED_EMAIL_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
RESERVED_EMAIL_SUFFIXES = (".example", ".invalid", ".test", ".localhost")


def _git() -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for repository privacy scanning")
    return git


def _tracked_files() -> list[Path]:
    result = subprocess.run(  # noqa: S603 - resolved Git binary with fixed arguments
        [_git(), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def _is_published(path: Path) -> bool:
    """True when ``path`` is inside the repository and not ignored by Git."""
    try:
        relative = path.resolve().relative_to(ROOT)
    except ValueError:
        return False
    result = subprocess.run(  # noqa: S603 - resolved Git binary with fixed arguments
        [_git(), "check-ignore", "--quiet", "--", relative.as_posix()],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    return result.returncode != 0


def patterns_path(argument: str | None, environ: Mapping[str, str]) -> Path | None:
    """Choose the private pattern list: --patterns, then the env var, then .local."""
    value = argument or environ.get(PATTERNS_ENV, "")
    if value:
        path = Path(value).expanduser()
        if not path.is_file():
            raise RuntimeError("private pattern list does not exist")
        if _is_published(path):
            raise RuntimeError(
                "private pattern list must be outside the repository or in an ignored path"
            )
        return path
    return DEFAULT_PATTERNS if DEFAULT_PATTERNS.is_file() else None


def load_patterns(path: Path | None) -> list[re.Pattern[str]]:
    if path is None:
        return []
    patterns: list[re.Pattern[str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            patterns.append(
                re.compile(value[3:] if value.startswith("re:") else re.escape(value), re.I)
            )
        except re.error as exc:
            raise RuntimeError(
                "private pattern list contains an invalid regular expression"
            ) from exc
    return patterns


def _history_revisions(environ: Mapping[str, str]) -> tuple[list[str], str]:
    """Select all history manually, or exactly the object range being pushed."""
    from_ref = environ.get("PRE_COMMIT_FROM_REF", "")
    to_ref = environ.get("PRE_COMMIT_TO_REF", "")
    if bool(from_ref) != bool(to_ref):
        raise RuntimeError("pre-push history range is incomplete")
    if not from_ref:
        return ["--all"], "fetched Git history"
    object_id = re.compile(r"[0-9a-fA-F]{40,64}")
    if not object_id.fullmatch(from_ref) or not object_id.fullmatch(to_ref):
        raise RuntimeError("pre-push history range is malformed")
    return [to_ref, f"^{from_ref}"], "pushed Git history"


def _history_findings(
    patterns: list[re.Pattern[str]], revisions: list[str]
) -> collections.Counter[str]:
    """Scan selected Git blobs without ever printing matched values or paths."""
    git = _git()
    result = subprocess.run(  # noqa: S603 - resolved Git binary with fixed arguments
        [git, "rev-list", "--objects", *revisions],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    findings: collections.Counter[str] = collections.Counter()
    scanned_content: set[str] = set()
    counted: set[tuple[str, str]] = set()
    for line in result.stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        object_id, raw_path = parts
        relative = Path(raw_path)
        if path_reason := _forbidden_path(relative):
            key = (object_id, path_reason)
            if key not in counted:
                findings[path_reason] += 1
                counted.add(key)
        if object_id in scanned_content:
            continue
        scanned_content.add(object_id)
        object_type = subprocess.run(  # noqa: S603 - fixed read-only Git object query
            [git, "cat-file", "-t", object_id],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if object_type != "blob":
            continue
        size = int(
            subprocess.run(  # noqa: S603 - fixed read-only Git object query
                [git, "cat-file", "-s", object_id],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        if size <= MAX_TEXT_BYTES:
            content = subprocess.run(  # noqa: S603 - fixed read-only Git object query
                [git, "cat-file", "blob", object_id],
                cwd=ROOT,
                check=True,
                capture_output=True,
            ).stdout
            if b"\0" not in content:
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    text = ""
                markdown = raw_path.casefold().endswith(".md")
                for _line, reason in _scan_text(text, patterns, markdown=markdown):
                    key = (object_id, reason)
                    if key not in counted:
                        findings[reason] += 1
                        counted.add(key)
    return findings


def _is_reserved_email_domain(domain: str) -> bool:
    normalized = domain.casefold().rstrip(".")
    return (
        normalized in RESERVED_EMAIL_DOMAINS
        or normalized.endswith(tuple(f".{domain}" for domain in RESERVED_EMAIL_DOMAINS))
        or normalized.endswith(RESERVED_EMAIL_SUFFIXES)
    )


def _cloudflare_networks() -> tuple[ipaddress.IPv4Network, ...]:
    """Cloudflare's published IPv4 edge ranges, as shipped for the gateway."""
    global _CLOUDFLARE
    if _CLOUDFLARE is None:
        networks = []
        if CLOUDFLARE_RANGES.is_file():
            for line in CLOUDFLARE_RANGES.read_text(encoding="utf-8").splitlines():
                entry = line.split("#", 1)[0].split()
                if not entry:
                    continue
                with contextlib.suppress(ValueError):
                    network = ipaddress.ip_network(entry[0])
                    # Only plausible edge blocks; a host route could hide anything.
                    if network.version == 4 and network.prefixlen <= 24 and network.is_global:
                        networks.append(network)
        _CLOUDFLARE = tuple(networks)
    return _CLOUDFLARE


_CLOUDFLARE: tuple[ipaddress.IPv4Network, ...] | None = None


def _is_public_ipv4(value: str, prefix: str | None = None) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return False  # version strings such as 1.2.300.4 are not addresses
    if address.is_unspecified or address == ipaddress.IPv4Address("255.255.255.255"):
        return False
    if prefix is not None:
        with contextlib.suppress(ValueError):
            if ipaddress.ip_network(f"{value}/{prefix}") in GENERIC_NETWORKS:
                return False
    if any(address in network for network in _cloudflare_networks()):
        return False
    return not any(address in network for network in DOCUMENTATION_NETWORKS)


def _forbidden_path(relative: Path) -> str | None:
    value = relative.as_posix()
    name = relative.name.casefold()
    if value.startswith("config/") and name.endswith(".sops.yaml"):
        return "encrypted host config must remain local and untracked"
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "runtime environment file must remain untracked"
    if name == "runtime.env" or name == "privacy-patterns":
        return "runtime environment file must remain untracked"
    if relative.parts and relative.parts[0].casefold() in {
        ".local",
        "attachments",
        "backups",
        "data",
        "logs",
        "run",
        "secrets",
    }:
        return "runtime data directory must remain untracked"
    if name.endswith((".db", ".sqlite", ".sqlite3", ".eml", ".mbox", ".pem", ".key", ".token")):
        return "runtime or credential material must remain untracked"
    if DATED_DOC_RE.search(value):
        return "dated operational note does not belong in the published docs"
    return None


def _scan_text(
    text: str, patterns: list[re.Pattern[str]], *, markdown: bool = False
) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in EMAIL_RE.finditer(line):
            if not _is_reserved_email_domain(match.group(2)):
                findings.append((line_number, "non-example email address"))
                break
        for match in HOME_RE.finditer(line):
            if match.group(1).casefold() not in NEUTRAL_HOME_USERS:
                findings.append((line_number, "user-specific absolute home path"))
                break
        for match in IPV4_RE.finditer(line):
            suffix = CIDR_SUFFIX_RE.match(line, match.end())
            if _is_public_ipv4(match.group(1), suffix.group(1) if suffix else None):
                findings.append((line_number, "non-loopback, non-documentation IPv4 address"))
                break
        if markdown and HEX_ID_RE.search(line):
            findings.append((line_number, "24-hex-digit identifier in documentation"))
        if any(pattern.search(line) for pattern in patterns):
            findings.append((line_number, "private pattern"))
    return findings


def scan_tree(
    files: list[Path], patterns: list[re.Pattern[str]]
) -> list[tuple[str, int | None, str]]:
    findings: list[tuple[str, int | None, str]] = []
    for path in files:
        relative = path.relative_to(ROOT)
        path_reason = _forbidden_path(relative)
        if path_reason:
            findings.append((relative.as_posix(), None, path_reason))
        if not path.exists() or not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES:
            continue
        content = path.read_bytes()
        if b"\0" in content:
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        markdown = relative.suffix.casefold() == ".md"
        for line_number, reason in _scan_text(text, patterns, markdown=markdown):
            findings.append((relative.as_posix(), line_number, reason))
    return sorted(set(findings), key=lambda item: (item[0], item[1] or 0, item[2]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--patterns",
        help=f"private pattern list outside the published tree (or ${PATTERNS_ENV})",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help=(
            "also scan every fetched blob, or the exact PRE_COMMIT_FROM_REF.."
            "PRE_COMMIT_TO_REF object range during pre-push"
        ),
    )
    args = parser.parse_args(argv)
    try:
        private_patterns = load_patterns(patterns_path(args.patterns, os.environ))
        tracked = _tracked_files()
    except (OSError, RuntimeError, subprocess.SubprocessError, UnicodeError) as exc:
        detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print(f"privacy scan could not start: {detail}", file=sys.stderr)
        return 2
    findings = scan_tree(tracked, private_patterns)
    if findings:
        for path, line_number, reason in findings:
            location = f"{path}:{line_number}" if line_number else path
            print(f"{location}: {reason}", file=sys.stderr)
        print(f"privacy scan failed with {len(findings)} finding(s)", file=sys.stderr)
        return 1
    history_label = ""
    if args.history:
        try:
            revisions, history_label = _history_revisions(os.environ)
            history_findings = _history_findings(private_patterns, revisions)
        except (OSError, RuntimeError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
            print(f"history privacy scan could not finish: {type(exc).__name__}", file=sys.stderr)
            return 2
        if history_findings:
            for reason, count in sorted(history_findings.items()):
                print(f"git-history: {reason}: {count} unique blob(s)", file=sys.stderr)
            print(
                "history privacy scan failed; matched values and paths were withheld",
                file=sys.stderr,
            )
            return 1
    suffix = f" and {history_label}" if args.history else ""
    pattern_note = f" with {len(private_patterns)} private pattern(s)" if private_patterns else ""
    print(f"privacy scan passed for {len(tracked)} repository files{pattern_note}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
