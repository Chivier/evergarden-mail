#!/usr/bin/env python3
"""Run gitleaks against exactly the files Git could add from this checkout.

Ignored runtime credentials and mail are deliberately present on deployment
hosts. A raw directory scan would inspect those local-only files and conflate
them with repository exposure. This scanner stages tracked plus unignored files
in a disposable directory, while the separate pre-push hook scans Git history.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".gitleaks.toml"
# Pinned in CI. Older releases silently ignore the [[allowlists]] table and
# fall back to a different rule set, so they are refused rather than trusted.
PINNED_VERSION = (8, 30, 1)
MINIMUM_VERSION = (8, 25, 0)


def gitleaks_version(gitleaks: str) -> tuple[int, ...]:
    result = subprocess.run(  # noqa: S603 - resolved gitleaks binary
        [gitleaks, "version"], check=True, capture_output=True, text=True
    )
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout)
    if match is None:
        raise RuntimeError("gitleaks version is unreadable")
    return tuple(int(part) for part in match.groups())


def _repository_files(git: str) -> list[Path]:
    result = subprocess.run(  # noqa: S603 - resolved Git binary with fixed arguments
        [git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = Path(os.fsdecode(raw))
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError("Git returned an unsafe repository path")
        paths.append(path)
    return paths


def main() -> int:
    git = shutil.which("git")
    gitleaks = shutil.which("gitleaks")
    if git is None or gitleaks is None:
        print("repository secret scan requires git and gitleaks", file=sys.stderr)
        return 2
    try:
        version = gitleaks_version(gitleaks)
        if version < MINIMUM_VERSION:
            print(
                "gitleaks {} is too old; install {} (see .gitleaks.toml)".format(
                    ".".join(map(str, version)), ".".join(map(str, PINNED_VERSION))
                ),
                file=sys.stderr,
            )
            return 2
        if version != PINNED_VERSION:
            print(
                "warning: gitleaks {} differs from the pinned {}".format(
                    ".".join(map(str, version)), ".".join(map(str, PINNED_VERSION))
                ),
                file=sys.stderr,
            )
        paths = _repository_files(git)
        with tempfile.TemporaryDirectory(prefix="evergarden-gitleaks-") as temporary:
            staging = Path(temporary)
            for relative in paths:
                source = ROOT / relative
                destination = staging / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_symlink():
                    destination.write_text(os.readlink(source), encoding="utf-8")
                elif source.is_file():
                    shutil.copyfile(source, destination)
            result = subprocess.run(  # noqa: S603 - resolved gitleaks binary
                [
                    gitleaks,
                    "detect",
                    "--source",
                    str(staging),
                    "--config",
                    str(CONFIG),
                    "--no-git",
                    "--no-banner",
                    "--redact",
                ],
                cwd=ROOT,
                check=False,
            )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"repository secret scan could not finish: {type(exc).__name__}", file=sys.stderr)
        return 2
    if result.returncode == 0:
        print(f"gitleaks passed for {len(paths)} repository files")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
