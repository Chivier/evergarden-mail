from __future__ import annotations

import contextlib
import multiprocessing
import threading
from types import SimpleNamespace

import pytest

from evergarden.approvals.service import ProviderNotAttempted
from evergarden.archive.sqlite_archive import ArchiveReader, ArchiveWriter, StaleMailboxSnapshot
from evergarden.mail.actions import MailActionExecutor
from evergarden.mail.sync import MailboxSyncBusy, ReadOnlyMailboxSync, account_sync_lock


def _hold_sync_lock(directory, ready, release):
    with account_sync_lock(directory, "gmail"):
        ready.set()
        assert release.wait(10)


@pytest.mark.parametrize("method", ["execute", "reconcile"])
@pytest.mark.parametrize(
    "operation,target", [("trash", "move"), ("mark", "mark"), ("send", "send")]
)
def test_provider_operation_waits_for_sync_in_another_process(tmp_path, method, operation, target):
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_hold_sync_lock, args=(tmp_path, ready, release))
    process.start()
    entered = threading.Event()
    executor = object.__new__(MailActionExecutor)
    executor.archive_writer = SimpleNamespace(data_dir=tmp_path)
    executor._account = lambda payload: SimpleNamespace(alias="gmail")
    setattr(
        executor,
        "_" + ("execute" if method == "execute" else "reconcile") + "_" + target,
        lambda *args: entered.set(),
    )
    failures = []

    def run():
        try:
            getattr(executor, method)({"operation": operation}, "key")
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=run)
    try:
        assert ready.wait(5)
        worker.start()
        assert not entered.wait(0.15), "provider operation ran while sync held account lock"
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        assert entered.is_set()
        assert not failures
    finally:
        release.set()
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join()
        assert process.exitcode == 0


def test_busy_mailbox_is_proved_not_attempted(tmp_path, monkeypatch):
    @contextlib.contextmanager
    def busy(*args, **kwargs):
        raise MailboxSyncBusy("busy")
        yield

    monkeypatch.setattr("evergarden.mail.actions.account_sync_lock", busy)
    executor = object.__new__(MailActionExecutor)
    executor.archive_writer = SimpleNamespace(data_dir=tmp_path)
    executor._account = lambda payload: SimpleNamespace(alias="gmail")
    executor._execute_move = lambda payload: pytest.fail("provider mutation attempted")
    with pytest.raises(ProviderNotAttempted):
        executor.execute({"operation": "trash"}, "key")


def test_snapshot_backoff_rereads_and_propagates_exhaustion(monkeypatch):
    delays = []
    monkeypatch.setattr("evergarden.mail.sync.time.sleep", delays.append)
    attempts = []

    def unstable(*args):
        attempts.append(args)
        raise StaleMailboxSnapshot("provider changed")

    with pytest.raises(StaleMailboxSnapshot):
        ReadOnlyMailboxSync._retry_folder_snapshot(
            unstable, object(), SimpleNamespace(alias="gmail"), "INBOX", 500
        )
    assert len(attempts) == 3
    assert delays == [2.0, 5.0]


def test_failed_attempt_visible_even_without_a_watermark(tmp_path):
    writer = ArchiveWriter(tmp_path)
    writer.set_sync_state("gmail", "INBOX", "777", 10)
    writer.record_sync_attempt("gmail", "INBOX", "run1", "failed", "SYNC_FAILED")
    writer.record_sync_attempt("gmail", "Deleted", "run1", "failed", "AUTHENTICATION_FAILED")
    rows = {r["folder"]: r for r in ArchiveReader(tmp_path).sync_status()}
    assert rows["INBOX"]["last_uid"] == 10
    assert rows["INBOX"]["last_attempt_status"] == "failed"
    assert rows["Deleted"]["last_synced_at"] is None
    assert rows["Deleted"]["last_attempt_reason"] == "AUTHENTICATION_FAILED"
