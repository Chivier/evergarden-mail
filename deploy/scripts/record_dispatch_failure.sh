#!/usr/bin/env bash
# OnFailure handler for evergarden-production-dispatch.service.
#
# The dispatcher runs twice an hour, so a successful later run resets its unit
# state and hides an earlier failure. This handler appends every failure to a
# private log. It then exits non-zero, latching the alarm unit in
# `systemctl --user --failed`, when a job failed on two consecutive runs or the
# dispatcher failed without writing any job report. A single failure is only
# logged: Outlook's intermittent "authenticated but not connected" fault
# exhausts the sync's retries a few times a day and clears on the next run.
# After reviewing the log, clear the alarm with
#   systemctl --user reset-failed evergarden-dispatch-alarm.service
set -euo pipefail

# The deployment root defaults to the checkout that contains this script.
evergarden_root="${EVERGARDEN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}"
reports="$evergarden_root/.local/data/reports"
log="$reports/dispatch-failures.jsonl"
umask 077
entry="$(python3 -I - "$reports" <<'EOF'
import datetime as dt
import json
import sys
import time
from pathlib import Path

reports = Path(sys.argv[1])
recent = time.time() - 15 * 60
failed = sorted(
    path for path in reports.glob("*/*.failed.json") if path.stat().st_mtime >= recent
)
persistent = []
for path in failed:
    # Order runs by write time; slot names change offset when DST ends.
    earlier = sorted(
        (item for item in path.parent.glob("*.json") if item.stat().st_mtime < path.stat().st_mtime),
        key=lambda item: item.stat().st_mtime,
    )
    if earlier and earlier[-1].name.endswith(".failed.json"):
        persistent.append(str(path.relative_to(reports)))
print(
    json.dumps(
        {
            "recorded_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "unit": "evergarden-production-dispatch.service",
            "failed_reports": [str(path.relative_to(reports)) for path in failed],
            "consecutive_failures": persistent,
            "latched": bool(persistent) or not failed,
        }
    )
)
EOF
)"
printf '%s\n' "$entry" >>"$log"
echo "evergarden dispatch failed: $entry" >&2
if [[ "$entry" == *'"latched": true'* ]]; then
  exit 1
fi
