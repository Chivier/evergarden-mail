from __future__ import annotations

import argparse
import fcntl
import json
import logging
import tempfile
import time
from pathlib import Path

from evergarden.audit.redaction import configure_logging
from evergarden.auth.maintenance import OAuthMaintenance
from evergarden.config import get_settings
from evergarden.mail.runtime import MailRuntime

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    settings = get_settings()
    if (
        settings.mode != "production"
        or settings.host_id != settings.active_writer
        or not settings.side_effects_enabled
        or not settings.oauth_callback_enabled
    ):
        raise RuntimeError("OAuth maintenance requires the active production credential owner")
    configure_logging(settings.log_level)
    runtime = MailRuntime(settings)
    lock = runtime.store.path.parent / ".oauth-maintenance.lock"
    with lock.open("a+") as handle:
        lock.chmod(0o600)
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        maintenance = OAuthMaintenance(runtime)
        while True:
            try:
                report = maintenance.step()
            except Exception as exc:
                if args.once:
                    raise
                # Keep the loop alive; a stale heartbeat makes the container
                # unhealthy if the fault persists.
                logger.error("OAuth maintenance step failed error_class=%s", type(exc).__name__)
                time.sleep(5)
                continue
            (Path(tempfile.gettempdir()) / "oauth-maintenance-heartbeat").touch(mode=0o600)
            if args.once:
                print(json.dumps(report))
                return
            if any(report.values()):
                logger.info("OAuth maintenance result=%s", json.dumps(report))
            time.sleep(5)


if __name__ == "__main__":
    main()
