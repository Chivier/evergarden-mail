from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from deploy.scripts import materialize_secrets as materialize

ACCOUNTS = json.loads(
    (Path(__file__).resolve().parents[1] / "config" / "mail-accounts.example.json").read_text(
        encoding="utf-8"
    )
)["accounts"]


def _documents(host: dict) -> dict[str, dict]:
    return {
        "common.sops.yaml": {
            "schema_version": 1,
            "mcp_resource": "https://mail.example.test/mcp",
            "oauth_issuer": "https://auth.example.test",
            "microsoft_oauth_client_id": "client-id",
            "microsoft_oauth_redirect_uri": "http://127.0.0.1:8788/oauth/callback/microsoft",
            "accounts": ACCOUNTS,
            "clients": {"mail-ui": {"scopes": ["mail:metadata", "mail:read"]}},
        },
        "host.sops.yaml": {
            "schema_version": 1,
            "credential_store_key": "k" * 44,
            "postgres_password": "pw",
            "compatibility_tokens": {"mail-ui": "token-value"},
            **host,
        },
    }


def _materialize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: dict, *extra: str
) -> dict[str, str]:
    documents = _documents(host)
    monkeypatch.setattr(materialize, "decrypt", lambda path, _key: documents[path.name])
    monkeypatch.setattr(
        sys,
        "argv",
        ["materialize", "--root", str(tmp_path), "--age-key", str(tmp_path / "age.key"), *extra],
    )
    assert materialize.main() == 0
    lines = (tmp_path / ".local" / "run" / "runtime.env").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines)


def test_fresh_host_document_materializes_a_read_only_single_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _materialize(tmp_path, monkeypatch, {})
    assert env["EVERGARDEN_HOST_ID"] == "default"
    assert env["EVERGARDEN_ACTIVE_WRITER"] == "default"
    assert env["EVERGARDEN_WRITER_EPOCH"] == "1"
    assert env["EVERGARDEN_SIDE_EFFECTS_ENABLED"] == "false"
    assert env["EVERGARDEN_TRASH_ACTIONS_ENABLED"] == "false"
    assert "EVERGARDEN_MODE" not in env
    registry = json.loads(
        (tmp_path / ".local" / "run" / "compatibility_tokens.json").read_text(encoding="utf-8")
    )
    assert registry["tokens"][0]["subject"] == "read-only:mail-ui"


def test_writer_host_document_keeps_operator_settings_on_regeneration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_root = tmp_path / ".local" / "run"
    run_root.mkdir(parents=True)
    (run_root / "runtime.env").write_text(
        "EVERGARDEN_MODE=production\n"
        "# operator note\n"
        "EVERGARDEN_AUTO_APPROVE=send,archive\n"
        "EVERGARDEN_HOST_ID=stale\n"
        "EVERGARDEN_SCHEDULE_TIMEZONE=Europe/Paris\n",
        encoding="utf-8",
    )
    host = {
        "host_id": "host-a",
        "writer_epoch": 2,
        "side_effects_enabled": True,
        "trash_actions_enabled": True,
    }
    env = _materialize(tmp_path, monkeypatch, host, "--allow-writer-control-change")
    assert env["EVERGARDEN_HOST_ID"] == "host-a"
    assert env["EVERGARDEN_ACTIVE_WRITER"] == "host-a"
    assert env["EVERGARDEN_WRITER_EPOCH"] == "2"
    assert env["EVERGARDEN_SIDE_EFFECTS_ENABLED"] == "true"
    assert env["EVERGARDEN_TRASH_ACTIONS_ENABLED"] == "true"
    assert env["EVERGARDEN_AUTO_APPROVE"] == "send,archive"
    assert env["EVERGARDEN_SCHEDULE_TIMEZONE"] == "Europe/Paris"
    assert "EVERGARDEN_MODE" not in env
    registry = json.loads((run_root / "compatibility_tokens.json").read_text(encoding="utf-8"))
    assert registry["tokens"][0]["subject"] == "production:mail-ui"


def test_existing_writer_control_is_never_flipped_silently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_root = tmp_path / ".local" / "run"
    run_root.mkdir(parents=True)
    original = (
        "EVERGARDEN_HOST_ID=host-a\n"
        "EVERGARDEN_ACTIVE_WRITER=host-a\n"
        "EVERGARDEN_WRITER_EPOCH=2\n"
        "EVERGARDEN_SIDE_EFFECTS_ENABLED=true\n"
        "EVERGARDEN_TRASH_ACTIONS_ENABLED=true\n"
    )
    (run_root / "runtime.env").write_text(original, encoding="utf-8")
    host = {"host_id": "host-a", "writer_epoch": 2, "side_effects_enabled": True}
    with pytest.raises(RuntimeError, match="EVERGARDEN_TRASH_ACTIONS_ENABLED"):
        _materialize(tmp_path, monkeypatch, host)
    assert (run_root / "runtime.env").read_text(encoding="utf-8") == original
    assert not (run_root / "compatibility_tokens.json").exists()
    env = _materialize(tmp_path, monkeypatch, {**host, "trash_actions_enabled": True})
    assert env["EVERGARDEN_TRASH_ACTIONS_ENABLED"] == "true"


def test_named_host_document_is_read_from_the_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    documents = _documents({"host_id": "host-a"})
    documents["host-a.sops.yaml"] = documents.pop("host.sops.yaml")
    monkeypatch.setattr(materialize, "decrypt", lambda path, _key: documents[path.name])
    argv = ["materialize", "--root", str(tmp_path), "--age-key", str(tmp_path / "age.key")]
    monkeypatch.setattr(sys, "argv", [*argv, "--host-document", "host-a.sops.yaml"])
    assert materialize.main() == 0
    monkeypatch.setattr(sys, "argv", [*argv, "--host-document", "../host-a.sops.yaml"])
    with pytest.raises(RuntimeError, match="file name"):
        materialize.main()


@pytest.mark.parametrize(
    "host",
    [
        {"host_id": "none"},
        {"host_id": "bad host"},
        {"active_writer": "bad writer"},
        {"writer_epoch": 0},
        {"writer_epoch": True},
        {"side_effects_enabled": "yes"},
        {"trash_actions_enabled": 1},
        {"host_id": "host-a", "active_writer": "host-b", "side_effects_enabled": True},
    ],
)
def test_invalid_host_writer_control_is_rejected(host: dict) -> None:
    with pytest.raises(RuntimeError, match="writer control"):
        materialize._host_control(host)


def test_preserved_env_ignores_missing_and_symlinked_files(tmp_path: Path) -> None:
    assert materialize._preserved_env(tmp_path / "missing.env", set()) == {}
    target = tmp_path / "target.env"
    target.write_text("A=1\n", encoding="utf-8")
    link = tmp_path / "link.env"
    link.symlink_to(target)
    assert materialize._preserved_env(link, set()) == {}
    assert materialize._preserved_env(target, {"B"}) == {"A": "1"}
