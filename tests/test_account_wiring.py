"""The services that enforce account policy must be given the loaded accounts.

``ApprovalService`` and ``ToolRuntime`` default to an empty inventory, and the
autouse conftest fixture replaces that default for tests. These checks make
sure no production construction site relies on the default.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from account_fixtures import TEST_ACCOUNTS

import apps.approval_ui.main as approval_ui
from evergarden.approvals.service import ApprovalService
from evergarden.config import Settings
from evergarden.mail.models import account_config_payload

ROOT = Path(__file__).resolve().parents[1]
GUARDED = {"ApprovalService", "ToolRuntime"}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def test_every_production_construction_passes_accounts() -> None:
    sites = []
    for directory in ("apps", "evergarden", "deploy"):
        for path in sorted((ROOT / directory).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _call_name(node) in GUARDED:
                    keywords = {keyword.arg for keyword in node.keywords}
                    sites.append((f"{path.relative_to(ROOT)}:{node.lineno}", keywords))
    assert sites, "expected at least one construction site"
    missing = [site for site, keywords in sites if "accounts" not in keywords]
    assert not missing, f"constructed without accounts=: {missing}"


def test_approval_ui_gives_its_service_the_configured_accounts(tmp_path: Path, monkeypatch):
    config = tmp_path / "accounts.json"
    config.write_text(json.dumps(account_config_payload(TEST_ACCOUNTS)))
    config.chmod(0o600)
    captured: dict = {}
    real_init = ApprovalService.__init__

    def record(self, *args, **kwargs):
        captured.update(kwargs)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(approval_ui.ApprovalService, "__init__", record)
    approval_ui.create_app(Settings(account_config_file=config))
    assert [account.alias for account in captured["accounts"]] == [
        account.alias for account in TEST_ACCOUNTS
    ]
