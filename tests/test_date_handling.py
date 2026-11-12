from __future__ import annotations

from pathlib import Path

import pytest
from conftest import message_record

from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter, _utc_boundary
from evergarden.mail.parse import date_to_iso, parse_message


def test_utc_boundary_converts_offsets_instead_of_comparing_them_as_text() -> None:
    # The stored form is the target: UTC rendered with a +00:00 suffix.
    assert _utc_boundary("2026-08-27T00:00:00+00:00") == "2026-08-27T00:00:00+00:00"
    assert _utc_boundary("2026-08-27T00:00:00Z") == "2026-08-27T00:00:00+00:00"
    # A naive value keeps its long-standing meaning of UTC.
    assert _utc_boundary("2026-08-27") == "2026-08-27T00:00:00+00:00"
    # The case that used to filter an hour off target: London local midnight is
    # 23:00 the previous day in UTC, and must compare as such.
    assert _utc_boundary("2026-08-27T00:00:00+01:00") == "2026-08-26T23:00:00+00:00"
    assert _utc_boundary("2026-08-27T09:00:00+08:00") == "2026-08-27T01:00:00+00:00"

    with pytest.raises(ValueError):
        _utc_boundary("not-a-date")


def _archive_with_dates(tmp_path: Path, dates: list[str]) -> Path:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    for index, received in enumerate(dates):
        writer.upsert(message_record(f"{index:024x}", uid=index + 1, received=received))
    writer.set_sync_state("gmail", "INBOX", "777", len(dates))
    return data


def test_local_midnight_boundary_selects_the_same_messages_as_its_utc_instant(
    tmp_path: Path,
) -> None:
    # 23:30 UTC on the 26th is 00:30 on the 27th in London: it belongs to
    # "today" for a caller on that clock.
    data = _archive_with_dates(
        tmp_path,
        [
            "2026-08-26T22:30:00+00:00",  # 23:30 London, the 26th
            "2026-08-26T23:30:00+00:00",  # 00:30 London, the 27th
            "2026-08-27T01:00:00+00:00",  # 02:00 London, the 27th
        ],
    )
    reader = ArchiveReader(data)

    london_midnight = reader.list_recent(since="2026-08-27T00:00:00+01:00")
    assert [row["date_received"] for row in london_midnight] == [
        "2026-08-27T01:00:00+00:00",
        "2026-08-26T23:30:00+00:00",
    ]
    # The same instant written as UTC must select exactly the same rows.
    assert london_midnight == reader.list_recent(since="2026-08-26T23:00:00+00:00")
    assert reader.count_messages(since="2026-08-27T00:00:00+01:00") == 2

    # A UTC-midnight boundary is a different instant and legitimately differs.
    assert reader.count_messages(since="2026-08-27T00:00:00+00:00") == 1


def test_before_boundary_also_honours_the_offset(tmp_path: Path) -> None:
    data = _archive_with_dates(tmp_path, ["2026-08-26T22:30:00+00:00", "2026-08-26T23:30:00+00:00"])
    reader = ArchiveReader(data)
    assert reader.count_messages(before="2026-08-27T00:00:00+01:00") == 1
    assert reader.count_messages(before="2026-08-27T00:00:00+00:00") == 2


def test_to_iso_rejects_an_absurd_year_instead_of_storing_it() -> None:
    assert date_to_iso("Fri, 4 Oct 2024 14:47:49 +0100") == "2024-10-04T13:47:49+00:00"
    # A naive header is read as UTC.
    assert date_to_iso("Fri, 4 Oct 2024 14:47:49") == "2024-10-04T14:47:49+00:00"
    # The archive really contained a message that parsed to the year 2611; such
    # a value outranks every genuine message in a DESC scan.
    assert date_to_iso("Wed, 24 Sep 2611 16:18:50 +0000") == ""
    assert date_to_iso("Mon, 1 Jan 1970 00:00:00 +0000") == ""
    assert date_to_iso("") == ""
    assert date_to_iso("total garbage") == ""


def test_stats_latest_ignores_a_malformed_date(tmp_path: Path) -> None:
    data = tmp_path / "archive"
    writer = ArchiveWriter(data)
    writer.upsert(message_record("a" * 24, received="2026-08-26T10:00:00+00:00"))
    writer.upsert(message_record("b" * 24, uid=2, received="2611-09-24T16:18:50+00:00"))
    writer.upsert(message_record("c" * 24, uid=3, received=""))
    writer.set_sync_state("gmail", "INBOX", "777", 3)

    stats = ArchiveReader(data).stats()
    assert stats["accounts"]["gmail"]["messages"] == 3
    assert stats["accounts"]["gmail"]["latest"] == "2026-08-26T10:00:00+00:00"


def _raw(headers: str, body: str = "hello") -> bytes:
    return (headers.rstrip("\n") + "\n\n" + body).encode()


def test_parser_recovers_a_date_swallowed_by_an_empty_subject() -> None:
    # An empty Subject makes the next line read as a folded continuation, so
    # the Subject becomes the Date text and the message is left with no Date.
    parsed = parse_message(
        _raw(
            "From: Sender <sender@example.test>\n"
            "Subject:\n"
            " Date: Fri, 4 Oct 2024 14:47:49 +0100\n"
            "Message-ID: <recovered@example.test>"
        )
    )
    assert parsed.subject == ""
    assert date_to_iso(parsed.date) == "2024-10-04T13:47:49+00:00"


def test_parser_leaves_a_real_subject_that_merely_starts_with_date() -> None:
    parsed = parse_message(
        _raw(
            "From: Someone <someone@example.test>\n"
            "Subject: Date: which day works for you?\n"
            "Date: Fri, 4 Oct 2024 14:47:49 +0100\n"
            "Message-ID: <untouched@example.test>"
        )
    )
    assert parsed.subject == "Date: which day works for you?"
    assert date_to_iso(parsed.date) == "2024-10-04T13:47:49+00:00"

    # With no Date header at all, unparseable text is still left alone.
    no_date = parse_message(
        _raw(
            "From: Someone <someone@example.test>\n"
            "Subject: Date: which day works for you?\n"
            "Message-ID: <nodate@example.test>"
        )
    )
    assert no_date.subject == "Date: which day works for you?"
    assert no_date.date == ""
