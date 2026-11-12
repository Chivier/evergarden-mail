from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from deploy.scripts import scheduler as scheduler_module
from deploy.scripts.scheduler import Scheduler, seconds_until_next_minute

ROOT = Path(__file__).resolve().parents[1]


class FakeProcess:
    def __init__(self, codes: list[int | None], final: int = 0) -> None:
        self.codes = codes
        self.final = final
        self.terminated = False
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        if self.killed or self.terminated:
            if self.terminated and not self.killed and self.final is None:
                raise subprocess.TimeoutExpired("due", timeout or 0)
            return -15 if self.final is None else self.final
        code = self.codes.pop(0) if self.codes else 0
        if code is None:
            raise subprocess.TimeoutExpired("due", timeout or 0)
        return code

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def test_seconds_until_next_minute() -> None:
    assert seconds_until_next_minute(120.0) == 60.0
    assert seconds_until_next_minute(150.0) == 30.0
    assert seconds_until_next_minute(179.5) == pytest.approx(0.5)


def test_runs_once_per_wall_clock_minute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    now = [30.0]
    started: list[float] = []

    def popen(command: list[str]) -> FakeProcess:
        started.append(now[0])
        assert command[-1] == "due"
        return FakeProcess([0])

    scheduler = Scheduler(heartbeat=tmp_path / "beat", clock=lambda: now[0], popen=popen)

    def wait(seconds: float) -> bool:
        now[0] += seconds
        return False

    monkeypatch.setattr(scheduler.stopping, "wait", wait)
    assert scheduler.run(max_runs=3) == 0
    assert started == [60.0, 120.0, 180.0]
    assert scheduler.failures == 0
    assert (tmp_path / "beat").exists()


def test_failures_are_counted_and_the_loop_continues(tmp_path: Path) -> None:
    processes = iter([FakeProcess([1]), FakeProcess([75]), FakeProcess([0])])
    scheduler = Scheduler(heartbeat=None, popen=lambda _command: next(processes))
    assert [scheduler.run_once() for _ in range(3)] == [1, 75, 0]
    assert scheduler.failures == 1
    assert scheduler.runs == 3


def test_long_runs_keep_the_heartbeat_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    beats: list[Path | None] = []
    monkeypatch.setattr(scheduler_module, "touch", beats.append)
    scheduler = Scheduler(
        heartbeat=tmp_path / "beat", popen=lambda _c: FakeProcess([None, None, 0])
    )
    assert scheduler.run_once() == 0
    assert len(beats) == 2


class RunningProcess:
    """A job that keeps running until it is signalled (or finishes on its own)."""

    def __init__(self, *, finishes_after: int | None = None, obeys_sigterm: bool = True) -> None:
        self.finishes_after = finishes_after
        self.obeys_sigterm = obeys_sigterm
        self.waits = 0
        self.terminated = False
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        self.waits += 1
        if self.killed:
            return -9
        if self.terminated and self.obeys_sigterm:
            return -15
        if self.finishes_after is not None and self.waits > self.finishes_after:
            return 0
        raise subprocess.TimeoutExpired("due", timeout or 0)

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def test_stop_lets_a_running_job_finish_inside_the_grace_period() -> None:
    job = RunningProcess(finishes_after=3)
    scheduler = Scheduler(heartbeat=None, popen=lambda _c: job, grace_seconds=60)
    scheduler.request_stop()
    assert scheduler.run_once() == 0
    assert not job.terminated and not job.killed
    assert scheduler.failures == 0


def test_stop_terminates_then_kills_a_job_that_outlives_the_grace_period(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scheduler_module, "TERMINATE_SECONDS", 0.01)
    polite = RunningProcess()
    scheduler = Scheduler(heartbeat=None, popen=lambda _c: polite, grace_seconds=0.01)
    scheduler.request_stop()
    assert scheduler.run_once() == -15
    assert polite.terminated and not polite.killed

    stubborn = RunningProcess(obeys_sigterm=False)
    scheduler = Scheduler(heartbeat=None, popen=lambda _c: stubborn, grace_seconds=0.01)
    scheduler.request_stop()
    assert scheduler.run_once() == -9
    assert stubborn.terminated and stubborn.killed
    assert scheduler.failures == 1


def test_scheduler_grace_fits_inside_the_compose_stop_grace_period() -> None:
    compose = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
    block = compose[compose.index("  scheduler:") :]
    period = int(block.split("stop_grace_period:", 1)[1].split("s", 1)[0])
    assert Scheduler(heartbeat=None).grace_seconds + scheduler_module.TERMINATE_SECONDS < period


def test_stop_before_the_next_minute_exits_without_running() -> None:
    scheduler = Scheduler(heartbeat=None, popen=lambda _c: pytest.fail("must not run"))
    scheduler.request_stop()
    assert scheduler.run() == 0
    assert scheduler.runs == 0


def test_sigterm_stops_the_real_process_promptly(tmp_path: Path) -> None:
    beat = tmp_path / "beat"
    process = subprocess.Popen(  # noqa: S603 - the interpreter running this test
        [sys.executable, "-m", "deploy.scripts.scheduler", "--heartbeat", str(beat)],
        cwd=ROOT,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not beat.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert beat.exists()
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=10) == 0
    assert "scheduler stopped" in process.stderr.read()
