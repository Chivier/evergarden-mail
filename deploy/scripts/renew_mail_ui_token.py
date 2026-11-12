"""Renew only the internal mail UI grant, preserving all external client grants."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
from pathlib import Path

from apps.mail_ui.main import _private_token
from deploy.scripts.materialize_secrets import atomic_private
from evergarden.auth.verifier import CompatibilityTokenVerifier


def renew(run_root: Path, backup_dir: Path, *, days: int = 45) -> dict:
    if not 1 <= days <= 45:
        raise ValueError("internal grant lifetime must be between 1 and 45 days")
    path = run_root / "compatibility_tokens.json"
    entries = CompatibilityTokenVerifier._load(path)
    token_hash = hashlib.sha256(_private_token(run_root / "mail_ui_mcp_token").encode()).hexdigest()
    matches = [entry for entry in entries if entry["client_id"] == "mail-ui"]
    if len(matches) != 1 or matches[0]["sha256"] != token_hash:
        raise ValueError("internal token does not match its registered grant")
    entry = matches[0]
    now = dt.datetime.now(dt.UTC)
    expiry = dt.datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00"))
    if expiry > now + dt.timedelta(days=7):
        return {"renewed": False, "expires_at": entry["expires_at"]}
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    saved = backup_dir / path.name
    shutil.copy2(path, saved)
    saved.chmod(0o600)
    document = json.loads(path.read_text())
    new_expiry = (now + dt.timedelta(days=days)).isoformat(timespec="seconds")
    for item in document["tokens"]:
        if item["client_id"] == "mail-ui":
            item["expires_at"] = new_expiry
    atomic_private(path, json.dumps(document, separators=(",", ":")))
    return {"renewed": True, "expires_at": new_expiry, "restart_services": ["mcp"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, default=Path(".local/run"))
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--days", type=int, default=45)
    args = parser.parse_args()
    print(json.dumps(renew(args.run_root, args.backup_dir, days=args.days)))


if __name__ == "__main__":
    main()
