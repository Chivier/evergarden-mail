"""Explicit example account inventory for tests.

The application has no built-in inventory; tests that need accounts pass this
one (or their own) explicitly.
"""

from __future__ import annotations

from evergarden.mail.models import AccountConfig

TEST_ACCOUNTS: tuple[AccountConfig, ...] = (
    AccountConfig(
        alias="work",
        address="mailbox@university.example",
        imap_host="outlook.office365.com",
        smtp_host="smtp.office365.com",
        auth_kind="oauth2",
        credential_record="microsoft:work",
        folders=("INBOX", "Archive", "Unrelated"),
        archive_folder="Archive",
        sent_folder="Sent Items",
        trash_folder="Deleted Items",
        safe_move_folders=("Archive", "Unrelated", "Later"),
        send_from_addresses=(
            "public-name@university.example",
            "mailbox@university.example",
        ),
    ),
    AccountConfig(
        alias="outlook",
        address="mailbox@outlook.example",
        imap_host="outlook.office365.com",
        smtp_host="smtp.office365.com",
        auth_kind="oauth2",
        credential_record="microsoft:outlook",
        folders=("Inbox", "Archive", "Important", "存档", "Unrelated"),
        archive_folder="Archive",
        sent_folder="Sent",
        trash_folder="Deleted Items",
        safe_move_folders=("Archive", "存档", "Important", "Projects", "Notes", "Unrelated"),
    ),
    AccountConfig(
        alias="gmail",
        address="mailbox@gmail.example",
        imap_host="imap.gmail.com",
        smtp_host="smtp.gmail.com",
        smtp_port=465,
        smtp_mode="ssl",
        auth_kind="password",
        credential_record="password:gmail",
        folders=("INBOX", "[Gmail]/All Mail", "[Gmail]/Important", "Unrelated"),
        archive_folder="[Gmail]/All Mail",
        sent_folder="[Gmail]/Sent Mail",
        trash_folder="[Gmail]/Trash",
        safe_move_folders=("[Gmail]/All Mail", "[Gmail]/Important", "Notes", "Unrelated"),
    ),
    AccountConfig(
        alias="icloud",
        address="mailbox@icloud.example",
        imap_host="imap.mail.me.com",
        smtp_host="smtp.mail.me.com",
        auth_kind="password",
        credential_record="password:icloud",
        folders=("INBOX", "Archive", "Unrelated"),
        archive_folder="Archive",
        sent_folder="Sent Messages",
        trash_folder="Deleted Messages",
        safe_move_folders=("Archive", "Unrelated"),
        copy_preserve_source_fallback=True,
    ),
)
