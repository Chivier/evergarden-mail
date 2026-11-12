from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

import pytest

from deploy.scripts.renew_mail_ui_token import renew


def _registry(root: Path, *, remaining_days: int = -1) -> dict:
    token = "internal-token-" + "x" * 48
    token_file = root / "mail_ui_mcp_token"
    token_file.write_text(token)
    token_file.chmod(0o600)
    entry = {
        "client_id": "mail-ui",
        "subject": "production:mail-ui",
        "audience": ["https://mail.test/mcp"],
        "scopes": ["mail:metadata"],
        "sha256": hashlib.sha256(token.encode()).hexdigest(),
        "expires_at": (dt.datetime.now(dt.UTC) + dt.timedelta(days=remaining_days)).isoformat(),
    }
    document = {"tokens": [{**entry, "client_id": "external", "sha256": "a" * 64}, entry]}
    path = root / "compatibility_tokens.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    return document


def test_renewal_preserves_external_grants_scopes_and_internal_secret(tmp_path: Path) -> None:
    original = _registry(tmp_path)
    secret = (tmp_path / "mail_ui_mcp_token").read_bytes()
    backup = tmp_path / "backup"
    result = renew(tmp_path, backup)
    current = json.loads((tmp_path / "compatibility_tokens.json").read_text())
    assert result["renewed"] is True
    assert current["tokens"][0] == original["tokens"][0]
    assert {k: v for k, v in current["tokens"][1].items() if k != "expires_at"} == {
        k: v for k, v in original["tokens"][1].items() if k != "expires_at"
    }
    assert json.loads((backup / "compatibility_tokens.json").read_text()) == original
    assert (tmp_path / "mail_ui_mcp_token").read_bytes() == secret
    assert (tmp_path / "compatibility_tokens.json").stat().st_mode & 0o077 == 0
    assert backup.stat().st_mode & 0o077 == 0
    assert renew(tmp_path, tmp_path / "unused-backup")["renewed"] is False
    assert not (tmp_path / "unused-backup").exists()


def test_renewal_rejects_mismatched_identity_and_unsafe_registry(tmp_path: Path) -> None:
    original = _registry(tmp_path)
    (tmp_path / "mail_ui_mcp_token").write_text("different-token-" + "y" * 48)
    with pytest.raises(ValueError, match="does not match"):
        renew(tmp_path, tmp_path / "backup")
    assert json.loads((tmp_path / "compatibility_tokens.json").read_text()) == original
    (tmp_path / "compatibility_tokens.json").chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        renew(tmp_path, tmp_path / "backup")
