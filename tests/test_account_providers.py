"""Provider traits are derived from each account's own configuration.

The five accounts below mirror a real multi-provider deployment (Microsoft 365
with a federated sign-in, Outlook.com, Gmail, iCloud and a Google Workspace
mailbox) using example addresses. Folder precedence must come from each
account's configured folders and its provider, never from its alias.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from conftest import message_record

from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter
from evergarden.mail.models import (
    AccountConfig,
    AccountConfigError,
    account_config_payload,
    folder_precedence_by_alias,
    load_account_configs,
    parse_account_config_payload,
)

WORK = "work"
OUTLOOK = "outlook"
GMAIL = "gmail"
ICLOUD = "icloud"
WORKSPACE = "workspace"

ACCOUNTS = (
    AccountConfig(
        alias=WORK,
        address="person@university.example",
        imap_host="outlook.office365.com",
        smtp_host="smtp.office365.com",
        auth_kind="oauth2",
        credential_record=f"microsoft:{WORK}",
        folders=("INBOX", "Archive", "Unrelated"),
        archive_folder="Archive",
        sent_folder="Sent Items",
        trash_folder="Deleted Items",
        safe_move_folders=("Archive", "Unrelated"),
    ),
    AccountConfig(
        alias=OUTLOOK,
        address="person@outlook.example",
        imap_host="outlook.office365.com",
        smtp_host="smtp.office365.com",
        auth_kind="oauth2",
        credential_record=f"microsoft:{OUTLOOK}",
        folders=("Inbox", "Archive", "Important", "存档", "Unrelated"),
        archive_folder="Archive",
        sent_folder="Sent",
        trash_folder="Deleted",
        safe_move_folders=("Archive", "Important", "存档", "Unrelated"),
    ),
    AccountConfig(
        alias=GMAIL,
        address="person@gmail.example",
        imap_host="imap.gmail.com",
        smtp_host="smtp.gmail.com",
        smtp_port=465,
        smtp_mode="ssl",
        credential_record=f"password:{GMAIL}",
        folders=("INBOX", "[Gmail]/All Mail", "[Gmail]/Important", "Unrelated"),
        archive_folder="[Gmail]/All Mail",
        sent_folder="[Gmail]/Sent Mail",
        trash_folder="[Gmail]/Trash",
        safe_move_folders=("[Gmail]/All Mail", "[Gmail]/Important", "Unrelated"),
    ),
    AccountConfig(
        alias=ICLOUD,
        address="person@icloud.example",
        imap_host="imap.mail.me.com",
        smtp_host="smtp.mail.me.com",
        credential_record=f"password:{ICLOUD}",
        folders=("INBOX", "Archive", "Unrelated"),
        archive_folder="Archive",
        sent_folder="Sent Messages",
        trash_folder="Deleted Messages",
        safe_move_folders=("Archive", "Unrelated"),
        copy_preserve_source_fallback=True,
    ),
    AccountConfig(
        alias=WORKSPACE,
        address="person@company.example",
        imap_host="imap.gmail.com",
        smtp_host="smtp.gmail.com",
        smtp_port=465,
        smtp_mode="ssl",
        credential_record=f"password:{WORKSPACE}",
        folders=("INBOX",),
        archive_folder="[Gmail]/All Mail",
        sent_folder="[Gmail]/Sent Mail",
        trash_folder="[Gmail]/Bin",
        safe_move_folders=("[Gmail]/All Mail",),
    ),
)


def _writer(path: Path) -> ArchiveWriter:
    return ArchiveWriter(path, folder_precedence=folder_precedence_by_alias(ACCOUNTS))


# (account, active provider locations, logical folder chosen once the
# configured precedence decides).
CASES = [
    (WORK, ("Archive", "Unrelated"), "Archive"),
    (WORK, ("Unrelated", "INBOX"), "INBOX"),
    (WORK, ("Later", "Unrelated"), "Unrelated"),
    (OUTLOOK, ("存档", "Important"), "Important"),
    (OUTLOOK, ("Unrelated", "存档"), "存档"),
    (OUTLOOK, ("Important", "Archive"), "Archive"),
    (OUTLOOK, ("Unrelated", "Inbox"), "Inbox"),
    # Gmail's All Mail and Important are label views: a real folder wins.
    (GMAIL, ("[Gmail]/All Mail", "Unrelated"), "Unrelated"),
    (GMAIL, ("[Gmail]/All Mail", "[Gmail]/Important"), "[Gmail]/Important"),
    (GMAIL, ("[Gmail]/Important", "Unrelated"), "Unrelated"),
    (GMAIL, ("Unrelated", "INBOX"), "INBOX"),
    (GMAIL, ("Receipts", "[Gmail]/All Mail"), "[Gmail]/All Mail"),
    (ICLOUD, ("Unrelated", "Archive"), "Archive"),
    (ICLOUD, ("Unrelated", "INBOX"), "INBOX"),
    # Only INBOX is configured: everything else falls back to name order.
    (WORKSPACE, ("[Gmail]/All Mail", "INBOX"), "INBOX"),
    (WORKSPACE, ("[Gmail]/Important", "[Gmail]/All Mail"), "[Gmail]/All Mail"),
    (WORKSPACE, ("[Gmail]/All Mail", "Receipts"), "Receipts"),
]


@pytest.mark.parametrize(("account", "locations", "expected"), CASES)
def test_logical_folder_precedence_matches_configured_accounts(
    tmp_path: Path, account: str, locations: tuple[str, str], expected: str
) -> None:
    writer = _writer(tmp_path)
    record = message_record("d" * 24, account=account, folder=locations[0], uid=10)
    writer.upsert(record, uid_validity="v1")
    writer.observe_location(
        dataclasses.replace(record, folder=locations[1], uid=20),
        uid_validity="v2",
        prefer_config_order=True,
    )
    assert ArchiveReader(tmp_path).get_message(record.stable_id)["folder"] == expected


def test_configured_precedence_now_also_decides_for_a_single_folder_mailbox(
    tmp_path: Path,
) -> None:
    """INBOX is configured for the Workspace mailbox, so it wins over any label.

    Before precedence was derived from the configuration, an alias without a
    built-in order picked the alphabetically first location ("Archive").
    """
    writer = _writer(tmp_path)
    record = message_record("e" * 24, account=WORKSPACE, folder="Archive", uid=10)
    writer.upsert(record, uid_validity="v1")
    writer.observe_location(
        dataclasses.replace(record, folder="INBOX", uid=20),
        uid_validity="v2",
        prefer_config_order=True,
    )
    assert ArchiveReader(tmp_path).get_message(record.stable_id)["folder"] == "INBOX"


def test_provider_is_detected_from_host_and_folders() -> None:
    providers = {account.alias: account.mail_provider for account in ACCOUNTS}
    assert providers == {
        WORK: "microsoft",
        OUTLOOK: "microsoft",
        GMAIL: "gmail",
        ICLOUD: "icloud",
        WORKSPACE: "gmail",
    }
    relay = dataclasses.replace(ACCOUNTS[2], imap_host="imap.relay.example")
    assert relay.mail_provider == "gmail"  # [Gmail]/ folders give it away
    plain = dataclasses.replace(ACCOUNTS[3], imap_host="imap.example.test", trash_folder="Trash")
    assert plain.mail_provider == "imap"
    assert plain.label_view_folders == frozenset()
    assert dataclasses.replace(plain, provider="gmail").mail_provider == "gmail"


def test_folder_precedence_ranks_gmail_views_last() -> None:
    by_alias = folder_precedence_by_alias(ACCOUNTS)
    assert by_alias[GMAIL] == ("INBOX", "Unrelated", "[Gmail]/Important", "[Gmail]/All Mail")
    assert by_alias[WORK] == ("INBOX", "Archive", "Unrelated")
    assert by_alias[OUTLOOK] == ("Inbox", "Archive", "Important", "存档", "Unrelated")
    assert by_alias[WORKSPACE] == ("INBOX",)
    google_mail = dataclasses.replace(
        ACCOUNTS[2],
        folders=("[Google Mail]/All Mail", "[Google Mail]/Starred", "INBOX"),
    )
    assert google_mail.folder_precedence == (
        "INBOX",
        "[Google Mail]/Starred",
        "[Google Mail]/All Mail",
    )
    # An "Important" folder outside Gmail is a real folder.
    assert "Important" not in ACCOUNTS[1].label_view_folders


def test_provider_field_is_optional_validated_and_round_trips() -> None:
    payload = account_config_payload(ACCOUNTS)
    assert all("provider" not in item for item in payload["accounts"])
    assert account_config_payload(parse_account_config_payload(payload)) == payload

    explicit = dataclasses.replace(ACCOUNTS[3], provider="imap")
    payload = account_config_payload((explicit,))
    assert payload["accounts"][0]["provider"] == "imap"
    assert parse_account_config_payload(payload)[0].mail_provider == "imap"

    payload["accounts"][0]["provider"] = "exchange"
    with pytest.raises(AccountConfigError, match="provider must be one of"):
        parse_account_config_payload(payload)


def test_missing_account_file_means_no_accounts() -> None:
    assert load_account_configs(None) == ()
