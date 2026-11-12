from __future__ import annotations

import dataclasses
import logging

import pytest
from pydantic import ValidationError

from deploy.scripts.check_repo_privacy import _history_revisions
from evergarden.audit.events import AuditChain
from evergarden.audit.redaction import (
    RedactingFilter,
    fingerprint,
    redact,
    redact_error_detail,
    redact_text,
    safe_json,
)
from evergarden.config import Settings


def test_settings_default_to_a_read_only_single_host() -> None:
    settings = Settings()
    assert settings.host_id == "default"
    assert settings.active_writer == "default"
    assert settings.is_active_writer is True
    assert settings.side_effects_enabled is False
    assert settings.trash_actions_enabled is False
    assert settings.auto_approve_kinds == frozenset()
    assert settings.mode == "read-only"
    assert settings.schedule_timezone == "UTC"


def test_side_effects_are_one_switch_on_the_active_writer_only() -> None:
    production = Settings(host_id="host-a", side_effects_enabled=True)
    assert production.active_writer == "host-a"
    assert production.mode == "production"
    # A blank writer means "this host", as in an empty runtime.env line.
    assert Settings(host_id="host-a", active_writer="").active_writer == "host-a"
    explicit = Settings(host_id="host-a", active_writer="host-a", writer_epoch=2)
    assert (explicit.mode, explicit.writer_epoch) == ("read-only", 2)
    # A legacy mode setting is no longer read; only the switch enables writes.
    assert Settings(host_id="host-a", mode="production").mode == "read-only"
    with pytest.raises(ValidationError, match="active writer host"):
        Settings(host_id="host-a", active_writer="host-b", side_effects_enabled=True)
    with pytest.raises(ValidationError, match="active writer host"):
        Settings(host_id="host-a", active_writer="none", side_effects_enabled=True)
    passive = Settings(host_id="host-a", active_writer="none")
    assert (passive.is_active_writer, passive.mode) == (False, "read-only")


@pytest.mark.parametrize("host_id", ["", "none", "-leading", "has space", "x" * 64, "a/b"])
def test_host_id_must_be_a_bounded_identifier(host_id: str) -> None:
    with pytest.raises(ValidationError, match="host id"):
        Settings(host_id=host_id)


def test_active_writer_and_schedule_timezone_are_validated() -> None:
    with pytest.raises(ValidationError, match="active writer"):
        Settings(active_writer="bad writer")
    with pytest.raises(ValidationError, match="timezone"):
        Settings(schedule_timezone="Mars/Olympus")
    assert Settings(schedule_timezone="Europe/Paris").schedule_timezone == "Europe/Paris"


def test_settings_read_writer_identity_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EVERGARDEN_HOST_ID", "mail-box.lan")
    monkeypatch.setenv("EVERGARDEN_ACTIVE_WRITER", "")
    monkeypatch.setenv("EVERGARDEN_WRITER_EPOCH", "2")
    monkeypatch.setenv("EVERGARDEN_SIDE_EFFECTS_ENABLED", "true")
    monkeypatch.setenv("EVERGARDEN_MODE", "production")
    monkeypatch.setenv("EVERGARDEN_SCHEDULE_TIMEZONE", "Asia/Shanghai")
    settings = Settings()
    assert (settings.host_id, settings.active_writer, settings.writer_epoch) == (
        "mail-box.lan",
        "mail-box.lan",
        2,
    )
    assert (settings.mode, settings.schedule_timezone) == ("production", "Asia/Shanghai")


def test_redaction_handles_nested_values_and_log_arguments() -> None:
    secret = "Bearer abcdefghijklmnopqrstuvwxyz"
    value = {"access_token": "secret", "nested": [secret, {"password": "pw"}]}
    safe = redact(value)
    assert safe["access_token"] == "[REDACTED]"
    assert "abcdefghijklmnopqrstuvwxyz" not in safe["nested"][0]
    assert safe["nested"][1]["password"] == "[REDACTED]"
    assert "secret" not in safe_json(value)
    assert "[REDACTED]" in redact_text("refresh_token=really-secret")
    assert len(fingerprint("x")) == 12

    record = logging.LogRecord("test", logging.INFO, __file__, 1, "auth=%s", (secret,), None)
    assert RedactingFilter().filter(record)
    assert "abcdefghijklmnopqrstuvwxyz" not in str(record.args)


def test_error_detail_keeps_provider_wording_without_secrets_or_addresses() -> None:
    detail = redact_error_detail(
        OSError("AUTHENTICATE failed for someone@example.com access_token=abc123secret")
    )
    assert "AUTHENTICATE failed" in detail
    assert "someone@example.com" not in detail
    assert "[ADDRESS]" in detail
    assert "abc123secret" not in detail

    for label in ("password", "app_password", "client_secret", "cookie"):
        assert "private-value" not in redact_error_detail(f"{label}=private-value")

    assert redact_error_detail(RuntimeError("verification code is 123456")) == (
        "verification code is [REDACTED]"
    )

    bounded = redact_error_detail(RuntimeError("x" * 500), limit=40)
    assert len(bounded) == 40
    assert bounded.endswith("...")


def test_audit_chain_is_redacted_and_tamper_evident() -> None:
    chain = AuditChain()
    first = chain.append(
        event_type="oauth.refresh",
        actor="worker",
        outcome="ok",
        metadata={"refresh_token": "secret", "account": "work"},
    )
    second = chain.append(
        event_type="mail.read", actor="codex", outcome="ok", metadata={"id": "abc"}
    )
    assert first.metadata["refresh_token"] == "[REDACTED]"
    assert second.previous_hash == first.event_hash
    assert chain.verify()
    chain.events[0] = dataclasses.replace(first, outcome="changed")
    assert not chain.verify()


def test_privacy_history_scan_uses_only_the_pre_push_object_range() -> None:
    assert _history_revisions({}) == (["--all"], "fetched Git history")
    from_ref = "a" * 40
    to_ref = "b" * 40
    assert _history_revisions({"PRE_COMMIT_FROM_REF": from_ref, "PRE_COMMIT_TO_REF": to_ref}) == (
        [to_ref, f"^{from_ref}"],
        "pushed Git history",
    )
    with pytest.raises(RuntimeError, match="incomplete"):
        _history_revisions({"PRE_COMMIT_FROM_REF": from_ref})
    with pytest.raises(RuntimeError, match="malformed"):
        _history_revisions({"PRE_COMMIT_FROM_REF": from_ref, "PRE_COMMIT_TO_REF": "--all"})
