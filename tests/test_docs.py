"""Checks that keep the public documentation in step with the code."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from evergarden.auth.api_keys import MAX_API_KEYS
from evergarden.auth.policy import TOOL_SCOPES, supported_scopes
from evergarden.config import Settings

ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_config_docs", ROOT / "tools" / "gen_config_docs.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _public_markdown() -> list[Path]:
    files = [
        *ROOT.glob("*.md"),
        *ROOT.glob("docs/**/*.md"),
        *ROOT.glob("deploy/**/*.md"),
        *ROOT.glob("tools/**/*.md"),
        *ROOT.glob(".github/**/*.md"),
    ]
    return sorted(
        path
        for path in files
        if "internal" not in path.relative_to(ROOT).parts
        and ".venv" not in path.relative_to(ROOT).parts
    )


FENCE = re.compile(r"^\s*(```|~~~)")


def _prose_lines(text: str) -> list[str]:
    """Lines outside fenced code blocks."""
    lines, fenced = [], False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            lines.append(line)
    return lines


def _slug(heading: str) -> str:
    text = re.sub(r"[`*_]|\[([^\]]*)\]\([^)]*\)", lambda m: m.group(1) or "", heading)
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    for line in _prose_lines(path.read_text(encoding="utf-8")):
        match = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if match:
            anchors.add(_slug(match.group(1)))
    return anchors


LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def test_settings_table_is_generated_from_settings() -> None:
    generator = _load_generator()
    assert set(generator.FIELDS) == set(Settings.model_fields)
    document = (ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")
    assert generator.updated_document(document) == document, (
        "docs/configuration.md is stale; run `uv run python tools/gen_config_docs.py`"
    )
    for name in Settings.model_fields:
        assert f"`EVERGARDEN_{name.upper()}`" in document


def test_every_compose_variable_is_documented() -> None:
    document = (ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    names = set(re.findall(r"^#?([A-Z][A-Z0-9_]+)=", example, flags=re.MULTILINE))
    assert names, ".env.example lists no variables"
    for name in sorted(names):
        assert f"`{name}`" in document, f"{name} from .env.example is not documented"


def test_runtime_example_only_names_real_settings() -> None:
    example = (ROOT / "runtime.env.example").read_text(encoding="utf-8")
    names = set(re.findall(r"^#?EVERGARDEN_([A-Z0-9_]+)=", example, flags=re.MULTILINE))
    unknown = sorted(name for name in names if name.casefold() not in Settings.model_fields)
    assert not unknown, f"runtime.env.example names unknown settings: {unknown}"


@pytest.mark.parametrize("path", _public_markdown(), ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(path: Path) -> None:
    problems = []
    for line in _prose_lines(path.read_text(encoding="utf-8")):
        for target in LINK.findall(line):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, flags=re.I):
                continue  # http(s), mailto, ...
            file_part, _, anchor = target.partition("#")
            resolved = (path.parent / file_part).resolve() if file_part else path
            if not resolved.exists():
                problems.append(f"missing target {target}")
                continue
            if anchor and resolved.suffix == ".md" and anchor not in _anchors(resolved):
                problems.append(f"missing anchor {target}")
    assert not problems, f"{path.relative_to(ROOT)}: {problems}"


# Words from the project's migration history that must not reappear in the
# public documentation. Deployment-specific names are checked separately by
# deploy/scripts/check_repo_privacy.py against EVERGARDEN_PRIVACY_PATTERNS.
FORBIDDEN_WORDS = re.compile(r"\b(shadow|parity|observation|phase [0-9]|alpha)\b", re.I)


@pytest.mark.parametrize("path", _public_markdown(), ids=lambda p: str(p.relative_to(ROOT)))
def test_public_docs_carry_no_private_history(path: Path) -> None:
    hits = [
        f"{number}: {match.group(0)}"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        for match in FORBIDDEN_WORDS.finditer(line)
    ]
    assert not hits, f"{path.relative_to(ROOT)}: {hits}"


def test_readmes_state_the_current_tool_count() -> None:
    count = len(TOOL_SCOPES)
    assert f"{count} tools" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{count} 个工具" in (ROOT / "README.zh-CN.md").read_text(encoding="utf-8")
    assert f"{count} scoped tools" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_screenshot_mock_matches_the_real_scopes_and_key_limit() -> None:
    # The README screenshots are rendered from tools/ui-preview/mock.py, which
    # imports no project code, so its copies of these values must be kept in step.
    mock = (ROOT / "tools" / "ui-preview" / "mock.py").read_text(encoding="utf-8")
    block = re.search(r'"mcp_scopes": \[(.*?)\]', mock, re.S)
    assert block is not None
    assert re.findall(r'"(mail:[a-z_-]+)"', block.group(1)) == supported_scopes()
    assert f'"max_keys": {MAX_API_KEYS},' in mock
