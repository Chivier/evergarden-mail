from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from croniter import croniter

from evergarden.archive.inventory import build_inventory
from evergarden.archive.sqlite_archive import ArchiveWriter
from evergarden.audit.redaction import configure_logging, redact_error_detail
from evergarden.automations.fence import FenceConfig, SideEffect, SideEffectFence
from evergarden.config import Settings, get_settings
from evergarden.database import (
    DuplicateJobRun,
    JobLease,
    WriterControlConflict,
    apply_migrations,
    reconcile_runtime_control,
    transition_runtime_control,
)
from evergarden.mail.runtime import MailRuntime, MailSyncBatchError
from evergarden.private_json import atomic_write_json

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAX_CATCH_UP_MINUTES = 30
MAIL_ONLY_JOBS = frozenset({"archive-sync", "oauth-watchdog", "weekly-rollover", "cold-export"})
MANIFEST_PATH = PROJECT_ROOT / "config" / "jobs.yaml"


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    """Load the job schedule.

    Jobs only read from providers and write the local archive and reports, so
    they run on the host that invokes the worker. The job lease makes each
    scheduled slot run at most once against a shared database.
    """
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("version") != 2
        or not isinstance(value.get("jobs"), dict)
    ):
        raise ValueError("job manifest is malformed")
    if set(value["jobs"]) != MAIL_ONLY_JOBS:
        raise ValueError("job manifest must contain exactly the mail-only job set")
    for name, job in value["jobs"].items():
        if not isinstance(job, dict) or set(job) - {"schedule", "trigger", "description"}:
            raise ValueError(f"job {name} has unsupported fields")
        if ("schedule" in job) == (job.get("trigger") == "manual"):
            raise ValueError(f"job {name} must be scheduled or manual-only")
        if "schedule" in job and not croniter.is_valid(str(job["schedule"])):
            raise ValueError(f"job {name} has an invalid schedule")
    return value


def default_slot(timezone: str) -> str:
    return dt.datetime.now(ZoneInfo(timezone)).replace(second=0, microsecond=0).isoformat()


def default_manual_slot(timezone: str) -> str:
    value = dt.datetime.now(ZoneInfo(timezone)).replace(microsecond=0)
    if value.second == 0:
        value = value.replace(second=1)
    return value.isoformat()


def parse_slot(slot: str) -> dt.datetime:
    value = dt.datetime.fromisoformat(slot.replace("Z", "+00:00"))
    return value.replace(tzinfo=value.tzinfo or dt.UTC)


def _write_report(
    report_dir: Path, job_id: str, slot: str, report: dict, *, suffix: str = ""
) -> Path:
    safe_slot = slot.replace(":", "-").replace("+", "_")
    path = report_dir / job_id / f"{safe_slot}{suffix}.json"
    atomic_write_json(path, report)
    return path


def _failure_report(job_id: str, slot: str, settings: Settings, exc: Exception) -> dict:
    """Record why a job died, so a failed slot is diagnosable without the journal."""
    report = {
        "job_id": job_id,
        "scheduled_slot": slot,
        "host": settings.host_id,
        "owner_epoch": settings.writer_epoch,
        "outcome": "FAILED",
        "error_class": type(exc).__name__,
        "error_detail": redact_error_detail(exc),
    }
    if isinstance(exc, MailSyncBatchError):
        report["failed_accounts"] = exc.failures
        report["attempted_accounts"] = [
            {
                "account": item["account"],
                "auth": item["auth"],
                "inserted": item["inserted"],
            }
            for item in exc.results
        ]
    return report


def run_job(job_id: str, slot: str) -> dict:
    settings = get_settings()
    manifest = load_manifest()
    if job_id not in manifest["jobs"]:
        raise ValueError(f"unknown job id: {job_id}")
    fence = SideEffectFence(
        FenceConfig(
            settings.host_id,
            settings.active_writer,
            settings.writer_epoch,
            settings.side_effects_enabled,
        )
    )
    base = {
        "job_id": job_id,
        "scheduled_slot": slot,
        "host": settings.host_id,
        "owner_epoch": settings.writer_epoch,
        "mode": settings.mode,
    }
    if job_id == "weekly-rollover":
        cutoff = dt.datetime.now(dt.UTC).date() - dt.timedelta(days=7)
        result = ArchiveWriter(settings.archive_dir).rollover_copy_only(
            scheduled_slot=slot, cutoff=cutoff
        )
        return {**base, "side_effects": "none", **result}
    if job_id == "cold-export":
        inventory = build_inventory(
            settings.archive_dir,
            source_host=settings.host_id,
            snapshot_tag=slot,
        )
        path = settings.report_dir / "cold-export" / f"inventory-{slot.replace(':', '-')}.json"
        atomic_write_json(path, inventory)
        return {
            **base,
            "message_count": inventory["message_count"],
            "inventory_sha256": inventory["inventory_sha256"],
        }
    if job_id == "archive-sync":
        results = MailRuntime(settings).sync_all()
        return {
            **base,
            "read_only": True,
            "accounts": [
                {
                    "account": item["account"],
                    "auth": item["auth"],
                    "inserted": item["inserted"],
                    "folders": {
                        folder: {
                            "fetched": value["fetched"],
                            "last_uid": value["last_uid"],
                            "historical_uid_discoveries": value["historical_uid_discoveries"],
                            "historical_uid_discoveries_remaining": value[
                                "historical_uid_discoveries_remaining"
                            ],
                            "locations_deactivated": value["locations_deactivated"],
                            "locations_reactivated": value["locations_reactivated"],
                            "location_flags_updated": value["location_flags_updated"],
                            "identity_conflicts": value["identity_conflicts"],
                        }
                        for folder, value in item["folders"].items()
                    },
                }
                for item in results
            ],
            "identity_conflicts_open": sum(
                len(value["identity_conflicts"])
                for item in results
                for value in item["folders"].values()
            ),
        }
    if job_id == "oauth-watchdog":
        readiness = MailRuntime(settings).refresh_readiness()
        return {
            **base,
            "credential_owner": settings.host_id,
            "dry_run": True,
            "results": readiness,
            "healthy": all(item["status"] == "ready" for item in readiness),
            "fence_probe": fence.probe(SideEffect.PROVIDER_TOKEN_REFRESH),
        }
    return {**base, "dry_run": True, "side_effects": "none"}


def execute_one(job_id: str, slot: str) -> tuple[int, dict]:
    settings = get_settings()
    try:
        with JobLease(
            database_url=settings.database_url,
            job_id=job_id,
            scheduled_slot=slot,
            host=settings.host_id,
            owner_epoch=settings.writer_epoch,
        ) as lease:
            try:
                report = run_job(job_id, slot)
            except Exception as exc:
                failure = _failure_report(job_id, slot, settings, exc)
                path = _write_report(settings.report_dir, job_id, slot, failure, suffix=".failed")
                logger.error(
                    "job failed job_id=%s slot=%s error_class=%s detail=%s",
                    job_id,
                    slot,
                    failure["error_class"],
                    failure["error_detail"],
                )
                lease.finish("FAILED")
                return 1, {"report": str(path), **failure}
            path = _write_report(settings.report_dir, job_id, slot, report)
            outcome = (
                "FAILED"
                if report.get("major_difference") or report.get("healthy") is False
                else "SUCCESS"
            )
            lease.finish(outcome)
            return (1 if outcome == "FAILED" else 0), {
                "report": str(path),
                "outcome": outcome,
                **report,
            }
    except DuplicateJobRun as exc:
        return 75, {"job_id": job_id, "outcome": "duplicate-rejected", "reason": str(exc)}


def due_jobs(at: dt.datetime, manifest: dict) -> list[str]:
    return sorted(
        job_id
        for job_id, job in manifest["jobs"].items()
        if job.get("trigger") != "manual" and croniter.match(str(job["schedule"]), at)
    )


def run_due(
    at: dt.datetime, manifest: dict, *, now: Callable[[], dt.datetime] | None = None
) -> tuple[int, list[dict]]:
    """Run jobs due at ``at``, then catch up minutes that passed meanwhile when ``now`` is given."""
    results = []
    overall = 0
    minute = at
    while True:
        for job_id in due_jobs(minute, manifest):
            code, report = execute_one(job_id, minute.isoformat())
            results.append(report)
            if code not in {0, 75}:
                overall = 1
        # systemd drops a timer trigger while this oneshot is still running,
        # so a slow run catches up the minutes it overlapped. The job lease
        # rejects any slot that another dispatcher already claimed.
        if now is None or minute - at >= dt.timedelta(minutes=MAX_CATCH_UP_MINUTES):
            break
        if minute >= now().replace(second=0, microsecond=0):
            break
        minute += dt.timedelta(minutes=1)
    return overall, results


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    migrate = sub.add_parser(
        "migrate", help="apply database migrations and reconcile the writer control row"
    )
    migrate.add_argument("--directory", type=Path, default=PROJECT_ROOT / "migrations")
    writer = sub.add_parser(
        "take-over-writer",
        help="move database writer control from another host to this one",
    )
    writer.add_argument("--expected-writer", required=True)
    writer.add_argument("--expected-epoch", type=int, required=True)
    run = sub.add_parser("run")
    run.add_argument("job_id")
    run.add_argument("--slot")
    due = sub.add_parser("due")
    due.add_argument(
        "--at", help="ISO-8601 minute; defaults to now in EVERGARDEN_SCHEDULE_TIMEZONE"
    )
    inventory = sub.add_parser("inventory")
    inventory.add_argument("--output", type=Path, required=True)
    inventory.add_argument("--source-host", required=True)
    inventory.add_argument("--snapshot-tag", required=True)
    args = parser.parse_args()
    settings = get_settings()
    configure_logging(settings.log_level)
    if args.command == "migrate":
        applied = apply_migrations(settings.database_url, args.directory)
        try:
            control = reconcile_runtime_control(
                settings.database_url,
                host=settings.host_id,
                active_writer=str(settings.active_writer),
                writer_epoch=settings.writer_epoch,
                side_effects_enabled=settings.side_effects_enabled,
            )
        except WriterControlConflict as exc:
            print(json.dumps({"applied": applied, "runtime_control_error": str(exc)}))
            return 1
        print(json.dumps({"applied": applied, "runtime_control": control}))
        return 0
    if args.command == "take-over-writer":
        if not settings.is_active_writer:
            raise RuntimeError("EVERGARDEN_ACTIVE_WRITER must name this host to take over")
        current = transition_runtime_control(
            settings.database_url,
            expected_writer=args.expected_writer,
            expected_epoch=args.expected_epoch,
            expected_side_effects=False,
            new_writer=settings.host_id,
            new_epoch=settings.writer_epoch,
            new_side_effects=settings.side_effects_enabled,
        )
        print(json.dumps(current))
        return 0
    if args.command == "inventory":
        value = build_inventory(
            settings.archive_dir, source_host=args.source_host, snapshot_tag=args.snapshot_tag
        )
        atomic_write_json(args.output, value)
        print(
            json.dumps(
                {
                    "output": str(args.output),
                    "messages": value["message_count"],
                    "sha256": value["inventory_sha256"],
                }
            )
        )
        return 0
    manifest = load_manifest()
    if args.command == "due":
        timezone = ZoneInfo(settings.schedule_timezone)
        at = (
            dt.datetime.fromisoformat(args.at).astimezone(timezone)
            if args.at
            else dt.datetime.now(timezone)
        ).replace(second=0, microsecond=0)
        overall, results = run_due(
            at, manifest, now=None if args.at else (lambda: dt.datetime.now(timezone))
        )
        print(json.dumps({"at": at.isoformat(), "jobs": results}, ensure_ascii=False))
        return overall
    job = manifest["jobs"].get(args.job_id)
    if job is None:
        raise ValueError(f"unknown job id: {args.job_id}")
    slot = args.slot or (
        default_manual_slot(settings.schedule_timezone)
        if job.get("trigger") == "manual"
        else default_slot(settings.schedule_timezone)
    )
    code, report = execute_one(args.job_id, slot)
    print(json.dumps(report, ensure_ascii=False), file=sys.stderr if code == 75 else sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
