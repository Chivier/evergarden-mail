"""The repository privacy gate. Sample values are assembled at runtime so that
this file itself passes the scan it tests."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from deploy.scripts import check_repo_privacy as privacy

AT = "@"
HOME = "/" + "home"


def _reasons(text: str, *, markdown: bool = False, patterns=()) -> list[str]:
    return [reason for _line, reason in privacy._scan_text(text, list(patterns), markdown=markdown)]


@pytest.mark.parametrize(
    "text",
    [
        f"contact alice{AT}example.com or bob{AT}mail.example",
        f"ops{AT}service.invalid and ci{AT}runner.test and x{AT}mail.example.org",
        f"{HOME}/evergarden/app and {HOME}/runner/work",
        "bind 127.0.0.1:8788, 0.0.0.0, 192.0.2.10, 198.51.100.7, 203.0.113.9",
        "resolver 127.0.0.11; version 1.2.300.4 and 3.12.7",
        "sha 3f2a9c1d0e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f in code",
        # Whole generic blocks (trusted-proxy defaults) and Cloudflare's
        # published edge ranges and addresses name nobody.
        "trust 10.0.0.0/8,172.16.0.0/12 192.168.0.0/16 and 240.0.0.0/4",
        "edge " + "173.245" + ".48.0/20 and hop " + "173.245" + ".48.10",
    ],
)
def test_generic_rules_accept_neutral_values(text: str) -> None:
    assert _reasons(text) == []


@pytest.mark.parametrize(
    ("text", "reason", "markdown"),
    [
        (f"mail me at someone{AT}gmail" + ".com", "non-example email address", False),
        (f"see {HOME}/alice/service/app", "user-specific absolute home path", False),
        ("/" + "Users/alice/Library", "user-specific absolute home path", False),
        (
            "server " + "10.0" + ".4.2 port 22",
            "non-loopback, non-documentation IPv4 address",
            False,
        ),
        ("dns " + "8.8" + ".8.8", "non-loopback, non-documentation IPv4 address", False),
        # A specific subnet or host inside a generic block is someone's network.
        ("net " + "172.20" + ".0.0/16", "non-loopback, non-documentation IPv4 address", False),
        ("net " + "10.1" + ".2.3/8", "non-loopback, non-documentation IPv4 address", False),
        ("host " + "192.168" + ".0.0", "non-loopback, non-documentation IPv4 address", False),
        (
            "ray " + "a4e2b7b7" + "689614fb" + "c0ffee12",
            "24-hex-digit identifier in documentation",
            True,
        ),
    ],
)
def test_generic_rules_flag_personal_values(text: str, reason: str, markdown: bool) -> None:
    assert _reasons(text, markdown=markdown) == [reason]


def test_hex_ids_are_only_flagged_in_markdown() -> None:
    value = "a4e2b7b7" + "689614fb" + "c0ffee12"
    assert _reasons(value) == []
    assert _reasons(value + "ff", markdown=True) == []


@pytest.mark.parametrize(
    ("path", "flagged"),
    [
        ("docs/incident-20" + "26-01-02.md", True),
        ("docs/internal/review-20" + "25-12.md", True),
        ("docs/user-guide.md", False),
        ("CHANGELOG.md", False),
        (".local/run/runtime.env", True),
        ("runtime.env", True),
        ("runtime.env.example", False),
        (".env", True),
        (".env.example", False),
        ("config/host.sops.yaml", True),
        ("archive/mail.eml", True),
        ("privacy-patterns", True),
    ],
)
def test_forbidden_paths(path: str, flagged: bool) -> None:
    assert (privacy._forbidden_path(Path(path)) is not None) is flagged


def test_private_patterns_load_literals_and_regexes(tmp_path: Path) -> None:
    source = tmp_path / "patterns"
    source.write_text("# comment\n\nmy-host\nre:acme[._-]corp\n", encoding="utf-8")
    patterns = privacy.load_patterns(source)
    assert _reasons("reach MY-HOST now", patterns=patterns) == ["private pattern"]
    assert _reasons("acme_corp", patterns=patterns) == ["private pattern"]
    assert _reasons("acme corp", patterns=patterns) == []
    source.write_text("re:(\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid regular expression"):
        privacy.load_patterns(source)
    assert privacy.load_patterns(None) == []


def test_pattern_list_must_live_outside_the_published_tree(tmp_path: Path) -> None:
    outside = tmp_path / "patterns"
    outside.write_text("x\n", encoding="utf-8")
    assert privacy.patterns_path(str(outside), {}) == outside
    assert privacy.patterns_path(None, {privacy.PATTERNS_ENV: str(outside)}) == outside
    with pytest.raises(RuntimeError, match="does not exist"):
        privacy.patterns_path(str(tmp_path / "missing"), {})
    published = privacy.ROOT / ".privacy-patterns.example"
    with pytest.raises(RuntimeError, match="outside the repository"):
        privacy.patterns_path(str(published), {})


def test_scan_tree_reports_location_and_reason_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(privacy, "ROOT", tmp_path)
    leaky = tmp_path / "docs" / "notes.md"
    leaky.parent.mkdir()
    leaky.write_text(f"ok\nwrite to me{AT}gmail" + ".com\n", encoding="utf-8")
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\0\x89PNG")
    findings = privacy.scan_tree([leaky, binary, tmp_path / "gone.txt"], [])
    assert findings == [("docs/notes.md", 2, "non-example email address")]


def test_main_passes_on_a_clean_tree_and_fails_on_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(privacy, "ROOT", tmp_path)
    monkeypatch.setattr(privacy, "DEFAULT_PATTERNS", tmp_path / ".local" / "privacy-patterns")
    clean = tmp_path / "README.md"
    clean.write_text("Evergarden\n", encoding="utf-8")
    monkeypatch.setattr(privacy, "_tracked_files", lambda: [clean])
    monkeypatch.delenv(privacy.PATTERNS_ENV, raising=False)
    assert privacy.main([]) == 0
    assert "privacy scan passed for 1 repository files" in capsys.readouterr().out

    patterns = tmp_path.parent / f"{tmp_path.name}-patterns"
    patterns.write_text("Evergarden\n", encoding="utf-8")
    assert privacy.main(["--patterns", str(patterns)]) == 1
    captured = capsys.readouterr()
    assert "README.md:1: private pattern" in captured.err
    assert "Evergarden\n" not in captured.err.replace("README.md:1: private pattern", "")

    assert privacy.main(["--patterns", str(tmp_path / "missing")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_history_mode_scans_blobs_without_printing_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    git = privacy._git()
    repository = tmp_path / "repo"
    repository.mkdir()

    def run(*args: str) -> None:
        subprocess.run(  # noqa: S603 - resolved Git binary, fixed arguments
            [git, "-c", "user.name=t", "-c", f"user.email=t{AT}example.com", *args],
            cwd=repository,
            check=True,
            capture_output=True,
        )

    run("init", "-q")
    leaked = repository / "notes.txt"
    leaked.write_text(f"someone{AT}gmail" + ".com\n", encoding="utf-8")
    run("add", "notes.txt")
    run("commit", "-qm", "add")
    leaked.write_text("clean\n", encoding="utf-8")
    run("commit", "-qam", "clean")
    monkeypatch.setattr(privacy, "ROOT", repository)
    monkeypatch.setattr(privacy, "DEFAULT_PATTERNS", repository / ".local" / "privacy-patterns")
    monkeypatch.delenv(privacy.PATTERNS_ENV, raising=False)
    monkeypatch.delenv("PRE_COMMIT_FROM_REF", raising=False)
    monkeypatch.delenv("PRE_COMMIT_TO_REF", raising=False)
    assert privacy.main([]) == 0
    capsys.readouterr()
    assert privacy.main(["--history"]) == 1
    err = capsys.readouterr().err
    assert "git-history: non-example email address: 1 unique blob(s)" in err
    assert "gmail" not in err
