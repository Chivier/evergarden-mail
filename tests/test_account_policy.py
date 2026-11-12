from __future__ import annotations

import dataclasses
import json

from evergarden.config import Settings
from evergarden.mail.models import AccountConfig
from evergarden.mail.policy import AccountPolicy


def _write_accounts(tmp_path, accounts):
    path = tmp_path / "accounts.json"
    path.write_text(
        json.dumps({"schema_version": 1, "accounts": [dataclasses.asdict(a) for a in accounts]})
    )
    path.chmod(0o600)
    return path


def test_policy_is_the_single_derivation_of_account_semantics(tmp_path) -> None:
    native = AccountConfig(alias="native", address="n@example.test", imap_host="imap.example.test")
    bridge_only = AccountConfig(
        alias="work",
        address="w@example.test",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        credential_record="google:work",
        send_from_addresses=("w@example.test",),
        enabled=False,
    )
    unrelated_disabled = AccountConfig(
        alias="other",
        address="o@example.test",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        credential_record="google:other",
        send_from_addresses=("o@example.test",),
        enabled=False,
    )
    settings = Settings(
        account_config_file=_write_accounts(tmp_path, [bridge_only, unrelated_disabled]),
        thunderbird_bridge_accounts="work, ghost",
        uidplus_move_accounts="native,missing",
    )

    policy = AccountPolicy.build(settings, (native,))
    assert policy.accounts == (native,)
    # Bridge mailboxes become readable; other disabled accounts and
    # configured-but-nonexistent bridge aliases do not.
    assert [a.alias for a in policy.read_accounts] == ["native", "work"]
    assert policy.receive_only_accounts == frozenset({"work"})
    # UIDPLUS applies only to enabled accounts.
    assert policy.uidplus_move_accounts == frozenset({"native"})


def test_policy_keeps_bridge_account_receive_only_when_natively_enabled(tmp_path) -> None:
    work = AccountConfig(
        alias="work",
        address="w@example.test",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        credential_record="google:work",
        send_from_addresses=("w@example.test",),
    )
    settings = Settings(
        account_config_file=_write_accounts(tmp_path, [work]),
        thunderbird_bridge_accounts="work",
    )
    policy = AccountPolicy.build(settings, (work,))
    assert [a.alias for a in policy.read_accounts] == ["work"]
    assert policy.receive_only_accounts == frozenset({"work"})


def test_mixed_case_bridge_setting_still_restricts_the_account(tmp_path) -> None:
    # Account aliases are casefolded on load; a mixed-case env entry must not
    # silently drop the receive-only restriction for an enabled bridge account.
    work = AccountConfig(
        alias="work",
        address="w@example.test",
        imap_host="imap.example.test",
        smtp_host="smtp.example.test",
        credential_record="google:work",
        send_from_addresses=("w@example.test",),
    )
    settings = Settings(
        account_config_file=_write_accounts(tmp_path, [work]),
        thunderbird_bridge_accounts="Work",
    )
    assert settings.thunderbird_bridge_account_set == frozenset({"work"})
    policy = AccountPolicy.build(settings, (work,))
    assert policy.receive_only_accounts == frozenset({"work"})
