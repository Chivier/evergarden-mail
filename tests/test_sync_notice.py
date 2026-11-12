from __future__ import annotations

import json

import pytest

from evergarden.mail.sync_notice import (
    MAX_ACCOUNTS,
    classify_sync_failure,
    summarize_sync_incomplete,
)


@pytest.mark.parametrize(
    ("error_class", "detail", "reason"),
    [
        ("gaierror", "[Errno -2] Name or service not known", "dns"),
        ("OSError", "[Errno -3] Temporary failure in name resolution", "dns"),
        ("ConnectionRefusedError", "[Errno 111] Connection refused", "refused"),
        ("OSError", "[Errno 111] Connection refused", "refused"),
        ("error", "b'[AUTHENTICATIONFAILED] Invalid credentials (Failure)'", "auth"),
        ("error", "b'LOGIN failed.'", "auth"),
        ("error", "AUTHENTICATE failed.", "auth"),
        ("CredentialNotFound", "credential record not found", "auth"),
        (
            "OAuthTokenRequestError",
            "Microsoft OAuth token request failed (400): interaction_required; AADSTS50076; "
            "interactive reauthorization required",
            "auth",
        ),
        (
            "OAuthTokenRequestError",
            "Microsoft OAuth token request failed (400): consent_required; AADSTS65001; "
            "interactive reauthorization required",
            "auth",
        ),
        (
            "OAuthTokenRequestError",
            "Google OAuth token request failed (401): invalid_client",
            "auth",
        ),
        (
            "OAuthTokenRequestError",
            "Google OAuth token request failed (400): invalid_request",
            "auth",
        ),
        (
            "OAuthTokenRequestError",
            "Microsoft OAuth token request failed (503): temporarily_unavailable",
            "other",
        ),
        ("OAuthTokenRequestError", "Google OAuth token request failed (429): slow_down", "other"),
        ("TimeoutError", "", "timeout"),
        ("SSLError", "_ssl.c:980: The handshake operation timed out", "timeout"),
        ("MailboxSyncBusy", "a sync of this mailbox is already running", "other"),
        ("error", "b'[NONEXISTENT] Unknown Mailbox: Archive'", "other"),
    ],
)
def test_failures_map_to_a_short_reason_class(error_class: str, detail: str, reason: str) -> None:
    assert classify_sync_failure(error_class, detail) == reason


def _incomplete(*accounts: dict) -> str:
    return json.dumps(
        {"error": "mail_sync_incomplete", "failed_accounts": list(accounts), "partial_results": []}
    )


def test_summary_names_each_mailbox_with_reason_and_secondary_detail() -> None:
    text = _incomplete(
        {
            "account": "personal",
            "error_class": "gaierror",
            "error_detail": "[Errno -2] Name or service not known",
        },
        {
            "account": "work",
            "error_class": "MailboxSyncIncomplete",
            "error_detail": "1 of 2 folders failed",
            "failed_folders": [
                {"folder": "Archive", "error_class": "TimeoutError", "error_detail": "timed out"}
            ],
        },
        "not an object",
    )
    assert summarize_sync_incomplete(text) == [
        {
            "account": "personal",
            "reason": "dns",
            "error_class": "gaierror",
            "detail": "[Errno -2] Name or service not known",
            "folders": [],
        },
        {
            "account": "work",
            "reason": "timeout",
            "error_class": "TimeoutError",
            "detail": "Archive: timed out",
            "folders": ["Archive"],
        },
    ]


def test_summary_is_bounded_and_redacted() -> None:
    accounts = [
        {
            "account": f"a{index}",
            "error_class": "error",
            "error_detail": "LOGIN failed for someone@example.com " + "x" * 2000,
        }
        for index in range(MAX_ACCOUNTS + 5)
    ]
    summary = summarize_sync_incomplete(_incomplete(*accounts))
    assert summary is not None
    assert len(summary) == MAX_ACCOUNTS
    assert all(len(item["detail"]) <= 300 for item in summary)
    assert "someone@example.com" not in json.dumps(summary)
    assert summary[0]["reason"] == "auth"


@pytest.mark.parametrize(
    "text",
    [
        "source message content changed after approval",
        "{not json",
        json.dumps({"error": "something_else", "failed_accounts": []}),
        json.dumps({"error": "mail_sync_incomplete", "failed_accounts": "x"}),
        json.dumps(["mail_sync_incomplete"]),
        "{" + " " * (300 * 1024),
    ],
)
def test_other_errors_are_not_summaries(text: str) -> None:
    assert summarize_sync_incomplete(text) is None
