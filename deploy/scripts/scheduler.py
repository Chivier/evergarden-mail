"""In-stack job scheduler: run the worker's ``due`` command once a minute.

This is the opt-in ``scheduler`` Compose profile. It replaces a host timer for
installs that do not want systemd or cron. Each tick starts a fresh
``python -m apps.worker.main due`` process, so a crash or a leaked connection
in one run never affects the next, and settings are re-read every minute.

``due`` already catches up the minutes a slow run overlapped, and the job
lease rejects a slot that another dispatcher (for example a host timer)
already claimed, so a missed or doubled tick is harmless.

SIGTERM or SIGINT stops the loop. Docker signals only this process, not the
``due`` child, so a running job is first left to finish on its own for up to
``--grace`` seconds; only then is it sent SIGTERM and, if it still has not
exited after a short second timeout, killed. Keep ``--grace`` plus that timeout
below the container's ``stop_grace_period``.
"""

from __future__ import annotations

import argparse
import logging
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

logger = logging.getLogger("evergarden.scheduler")

DEFAULT_COMMAND = (sys.executable, "-m", "apps.worker.main", "due")
DEFAULT_HEARTBEAT = Path("/tmp/scheduler-heartbeat")  # noqa: S108 - container tmpfs
POLL_SECONDS = 5.0
# Time a job gets to exit after SIGTERM before it is killed.
TERMINATE_SECONDS = 10.0


def seconds_until_next_minute(now: float) -> float:
    """Seconds from ``now`` to the next whole minute (never zero)."""
    remainder = 60.0 - (now % 60.0)
    return remainder if remainder > 0 else 60.0


def touch(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.touch()
    except OSError as exc:  # pragma: no cover - read-only heartbeat path
        logger.warning(
            "scheduler heartbeat could not be written error_class=%s", type(exc).__name__
        )


class Scheduler:
    def __init__(
        self,
        command: Sequence[str] = DEFAULT_COMMAND,
        *,
        heartbeat: Path | None = DEFAULT_HEARTBEAT,
        grace_seconds: float = 100.0,
        clock: Callable[[], float] = time.time,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        self.command = tuple(command)
        self.heartbeat = heartbeat
        self.grace_seconds = grace_seconds
        self.clock = clock
        self.popen = popen
        self.stopping = threading.Event()
        self.runs = 0
        self.failures = 0

    def request_stop(self, *_args: object) -> None:
        self.stopping.set()

    def run_once(self) -> int:
        """Run one ``due`` process to completion, or stop it when asked to."""
        self.runs += 1
        process = self.popen(list(self.command))
        deadline: float | None = None
        while True:
            try:
                code = process.wait(timeout=POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                touch(self.heartbeat)
                if not self.stopping.is_set():
                    continue
                if deadline is None:
                    logger.info(
                        "scheduler stopping; waiting up to %ss for the running job",
                        self.grace_seconds,
                    )
                    deadline = time.monotonic() + self.grace_seconds
                if time.monotonic() < deadline:
                    continue
                logger.warning("running job outlived the grace period; terminating it")
                process.terminate()
                try:
                    code = process.wait(timeout=TERMINATE_SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    code = process.wait()
                break
        if code not in (0, 75):
            self.failures += 1
            logger.warning("scheduled run failed exit_code=%s", code)
        return code

    def run(self, *, max_runs: int | None = None) -> int:
        logger.info("scheduler started; running due jobs every minute")
        touch(self.heartbeat)
        # Start at the next minute boundary, then once per wall-clock minute.
        last_minute = int(self.clock() // 60)
        while not self.stopping.is_set():
            # Sleep in short slices so the heartbeat stays fresh and a stop
            # request is honoured promptly.
            if self.stopping.wait(min(POLL_SECONDS, seconds_until_next_minute(self.clock()))):
                break
            touch(self.heartbeat)
            minute = int(self.clock() // 60)
            if minute == last_minute:
                continue
            last_minute = minute
            self.run_once()
            touch(self.heartbeat)
            if max_runs is not None and self.runs >= max_runs:
                break
        logger.info("scheduler stopped runs=%s failures=%s", self.runs, self.failures)
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--heartbeat", type=Path, default=DEFAULT_HEARTBEAT)
    parser.add_argument("--grace", type=float, default=100.0, help="seconds; default 100")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    scheduler = Scheduler(heartbeat=args.heartbeat, grace_seconds=args.grace)
    signal.signal(signal.SIGTERM, scheduler.request_stop)
    signal.signal(signal.SIGINT, scheduler.request_stop)
    return scheduler.run()


if __name__ == "__main__":
    raise SystemExit(main())
