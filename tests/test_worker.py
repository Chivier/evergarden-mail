from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import sys
import zoneinfo
from pathlib import Path

import pytest
import yaml

from apps.worker import main as worker
from evergarden.archive.inventory import INVENTORY_SCOPE, INVENTORY_VERSION, build_inventory
from evergarden.config import Settings
from evergarden.private_json import atomic_write_json

INVENTORY_FIELDS = frozenset(
    {
        "version",
        "scope",
        "source_host",
        "snapshot_tag",
        "generated_at",
        "message_count",
        "inventory_sha256",
        "shard_integrity",
        "messages",
    }
)


def _inventory(archive_dir: Path, when: dt.datetime) -> dict:
    return build_inventory(
        archive_dir,
        source_host="test-host",
        snapshot_tag=when.strftime("inventory-%Y%m%dT%H%M%SZ"),
        generated_at=when,
    )


def test_inventory_is_strictly_mail_only_and_content_free(archive_dir: Path) -> None:
    generated = dt.datetime(2026, 8, 17, 8, 30, tzinfo=dt.UTC)
    inventory = _inventory(archive_dir, generated)
    assert set(inventory) == INVENTORY_FIELDS
    assert (
        inventory["inventory_sha256"]
        == hashlib.sha256(
            json.dumps(inventory["messages"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    with pytest.raises(ValueError, match="timezone"):
        _inventory(archive_dir, generated.replace(tzinfo=None))
    assert inventory["version"] == INVENTORY_VERSION == 4
    assert inventory["scope"] == INVENTORY_SCOPE == "mail-only"
    assert inventory["message_count"] == 2
    assert set(inventory["shard_integrity"].values()) == {"ok"}
    serialized = json.dumps(inventory)
    for forbidden in (
        "body_text",
        "body_html",
        'subject"',
        'sender_email"',
        "digest_summaries",
        "automation_previews",
        "automation_state",
        "ticktick",
        "discord",
        "weixin",
    ):
        assert forbidden not in serialized.lower()


def test_atomic_private_writer_is_private_and_rejects_symlink_targets(tmp_path: Path) -> None:
    output = tmp_path / "private" / "report.json"
    atomic_write_json(output, {"safe": True})
    assert json.loads(output.read_text(encoding="utf-8")) == {"safe": True}
    assert output.parent.stat().st_mode & 0o077 == 0
    assert output.stat().st_mode & 0o077 == 0

    target = tmp_path / "target.json"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        atomic_write_json(link, {"safe": True})
    assert target.read_text(encoding="utf-8") == "keep"

    real_dir = tmp_path / "real"
    real_dir.mkdir()
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(ValueError, match="directory"):
        atomic_write_json(linked_dir / "output.json", {"safe": True})


def _settings(tmp_path: Path, archive_dir: Path) -> Settings:
    return Settings(
        archive_dir=archive_dir,
        report_dir=tmp_path / "reports",
        credential_db=tmp_path / "secrets" / "credentials.db",
        credential_key_file=tmp_path / "secrets" / "key",
        database_url="postgresql://unused",
        oauth_jwks_url=None,
    )


def test_manifest_allows_exactly_mail_only_jobs_and_manual_jobs_are_never_due(
    tmp_path: Path,
) -> None:
    manifest = worker.load_manifest()
    assert worker.MANIFEST_PATH.name == "jobs.yaml"
    assert set(manifest["jobs"]) == worker.MAIL_ONLY_JOBS
    assert "timezone" not in manifest
    at = dt.datetime(2026, 8, 17, 9, 3, tzinfo=dt.timezone(dt.timedelta(hours=1)))
    assert worker.due_jobs(at, manifest) == ["archive-sync"]
    at_watchdog = at.replace(minute=5)
    assert worker.due_jobs(at_watchdog, manifest) == ["oauth-watchdog"]
    assert worker.due_jobs(at.replace(minute=7), manifest) == []
    assert {name for name, job in manifest["jobs"].items() if job.get("trigger") == "manual"} == {
        "cold-export",
        "weekly-rollover",
    }

    bad = copy.deepcopy(manifest)
    bad["jobs"]["digest"] = {"schedule": "0 8 * * *"}
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(bad), encoding="utf-8")
    with pytest.raises(ValueError, match="mail-only"):
        worker.load_manifest(path)


def test_due_catches_up_slots_that_passed_while_an_earlier_job_ran(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = worker.load_manifest()
    zone = dt.timezone(dt.timedelta(hours=1))
    start = dt.datetime(2026, 9, 26, 22, 3, tzinfo=zone)
    clock = iter(
        [start + dt.timedelta(minutes=2, seconds=40)] * 3
        + [start + dt.timedelta(minutes=3, seconds=5)] * 5
    )
    ran = []
    monkeypatch.setattr(
        worker,
        "execute_one",
        lambda job_id, slot: ran.append((job_id, slot)) or (0, {"job_id": job_id}),
    )
    overall, results = worker.run_due(start, manifest, now=lambda: next(clock))
    assert overall == 0
    assert ran == [
        ("archive-sync", "2026-09-26T22:03:00+01:00"),
        ("oauth-watchdog", "2026-09-26T22:05:00+01:00"),
    ]
    assert len(results) == 2

    ran.clear()
    assert worker.run_due(start, manifest) == (0, [{"job_id": "archive-sync"}])
    assert ran == [("archive-sync", "2026-09-26T22:03:00+01:00")]


@pytest.mark.parametrize(
    "mutation", ["version", "host", "unknown-field", "trigger", "schedule", "not-a-mapping"]
)
def test_manifest_rejects_malformed_or_unsafe_jobs(tmp_path: Path, mutation: str) -> None:
    manifest = yaml.safe_load(worker.MANIFEST_PATH.read_text(encoding="utf-8"))
    if mutation == "version":
        manifest["version"] = 1
    elif mutation == "host":
        # Host ownership comes from settings; a manifest cannot pin a host.
        manifest["jobs"]["archive-sync"]["active_host"] = "host-b"
    elif mutation == "unknown-field":
        manifest["jobs"]["archive-sync"]["side_effect"] = "smtp-send"
    elif mutation == "trigger":
        manifest["jobs"]["archive-sync"]["trigger"] = "manual"
    elif mutation == "schedule":
        manifest["jobs"]["archive-sync"]["schedule"] = "every hour"
    elif mutation == "not-a-mapping":
        manifest["jobs"]["archive-sync"] = "3 * * * *"
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        worker.load_manifest(path)


def test_worker_mail_jobs_and_manual_maintenance(
    tmp_path: Path, archive_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, archive_dir)
    generated = dt.datetime(2026, 8, 17, 12, 0, tzinfo=dt.UTC)
    monkeypatch.setattr(worker, "get_settings", lambda: settings)

    class FakeRuntime:
        def __init__(self, _settings):
            pass

        def sync_all(self):
            return [
                {
                    "account": "gmail",
                    "auth": "ok",
                    "inserted": 0,
                    "folders": {
                        "INBOX": {
                            "fetched": 0,
                            "last_uid": 10,
                            "historical_uid_discoveries": 2,
                            "historical_uid_discoveries_remaining": 0,
                            "locations_deactivated": 0,
                            "locations_reactivated": 0,
                            "location_flags_updated": 1,
                            "identity_conflicts": [{"uid": 11, "stable_id": "a" * 24}],
                        }
                    },
                }
            ]

        def refresh_readiness(self):
            return [{"account": "outlook", "status": "ready", "has_refresh_token": True}]

    monkeypatch.setattr(worker, "MailRuntime", FakeRuntime)
    slot = (generated + dt.timedelta(minutes=1)).isoformat()
    synced = worker.run_job("archive-sync", slot)
    assert synced["read_only"] is True
    assert synced["identity_conflicts_open"] == 1
    assert synced["accounts"][0]["folders"]["INBOX"]["identity_conflicts"] == [
        {"uid": 11, "stable_id": "a" * 24}
    ]
    assert worker.run_job("oauth-watchdog", slot)["dry_run"] is True
    assert worker.run_job("oauth-watchdog", slot)["healthy"] is True
    monkeypatch.setattr(
        FakeRuntime,
        "refresh_readiness",
        lambda _self: [{"account": "work", "status": "authorization_required"}],
    )
    assert worker.run_job("oauth-watchdog", slot)["healthy"] is False
    assert worker.run_job("oauth-watchdog", slot)["fence_probe"]["allowed"] is False
    cold = worker.run_job("cold-export", slot)
    assert cold["message_count"] == 2
    cold_report = json.loads(
        (
            settings.report_dir / "cold-export" / f"inventory-{slot.replace(':', '-')}.json"
        ).read_text()
    )
    assert cold_report["scope"] == "mail-only"
    assert worker.run_job("weekly-rollover", slot)["side_effects"] == "none"
    for removed in ("parity", "side-effect-fence-audit", "digest-0830", "parcel-watchdog"):
        with pytest.raises(ValueError):
            worker.run_job(removed, slot)


def test_execute_one_rejects_duplicate_and_writes_private_report(
    tmp_path: Path, archive_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, archive_dir)
    monkeypatch.setattr(worker, "get_settings", lambda: settings)

    class Lease:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def finish(self, outcome):
            self.outcome = outcome

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(worker, "JobLease", Lease)
    monkeypatch.setattr(
        worker, "run_job", lambda job_id, slot: {"job_id": job_id, "slot": slot, "dry_run": True}
    )
    code, report = worker.execute_one("cold-export", "slot")
    assert code == 0
    assert report["outcome"] == "SUCCESS"
    assert Path(report["report"]).stat().st_mode & 0o077 == 0

    monkeypatch.setattr(
        worker,
        "run_job",
        lambda _job_id, _slot: {
            "healthy": False,
            "results": [{"account": "work", "status": "authorization_required"}],
        },
    )
    code, report = worker.execute_one("oauth-watchdog", "unhealthy-slot")
    assert code == 1
    assert report["outcome"] == "FAILED"
    assert (
        json.loads(Path(report["report"]).read_text())["results"][0]["status"]
        == "authorization_required"
    )

    class Duplicate(Lease):
        def __enter__(self):
            raise worker.DuplicateJobRun("duplicate")

    monkeypatch.setattr(worker, "JobLease", Duplicate)
    code, report = worker.execute_one("cold-export", "slot")
    assert code == 75
    assert report["outcome"] == "duplicate-rejected"


def test_execute_one_records_a_failed_slot_as_a_private_report(
    tmp_path: Path, archive_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, archive_dir)
    monkeypatch.setattr(worker, "get_settings", lambda: settings)
    finished: list[str] = []

    class Lease:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def finish(self, outcome):
            finished.append(outcome)

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(worker, "JobLease", Lease)
    batch = worker.MailSyncBatchError(
        [{"account": "work", "auth": "ok", "inserted": 2}],
        [
            {
                "account": "outlook",
                "error_class": "ConnectError",
                "error_detail": "provider refused the connection",
            }
        ],
    )

    def failing(job_id, slot):
        raise batch

    monkeypatch.setattr(worker, "run_job", failing)
    code, report = worker.execute_one("archive-sync", "2026-08-26T20:03:00+01:00")
    assert code == 1
    assert finished == ["FAILED"]
    assert report["outcome"] == "FAILED"
    assert report["error_class"] == "MailSyncBatchError"
    assert report["failed_accounts"][0]["error_detail"] == "provider refused the connection"
    assert report["attempted_accounts"] == [{"account": "work", "auth": "ok", "inserted": 2}]

    path = Path(report["report"])
    assert path.name.endswith(".failed.json")
    assert path.stat().st_mode & 0o077 == 0
    # A failed slot must not masquerade as a successful report.
    assert not (path.parent / "2026-08-26T20-03-00_01-00.json").exists()


def test_worker_cli_migrate_inventory_due_and_single_run(
    tmp_path: Path,
    archive_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path, archive_dir)
    monkeypatch.setattr(worker, "get_settings", lambda: settings)
    monkeypatch.setattr(worker, "configure_logging", lambda _level: None)
    monkeypatch.setattr(worker, "apply_migrations", lambda *_args: ["001_initial.sql"])
    reconciled: list[dict] = []
    monkeypatch.setattr(
        worker,
        "reconcile_runtime_control",
        lambda _url, **kwargs: reconciled.append(kwargs) or {**kwargs, "changed": True},
    )
    monkeypatch.setattr(sys, "argv", ["evergarden-worker", "migrate"])
    assert worker.main() == 0
    migrated = json.loads(capsys.readouterr().out)
    assert migrated["applied"] == ["001_initial.sql"]
    assert reconciled == [
        {
            "host": "default",
            "active_writer": "default",
            "writer_epoch": 1,
            "side_effects_enabled": False,
        }
    ]
    assert migrated["runtime_control"]["changed"] is True

    def conflict(_url, **_kwargs):
        raise worker.WriterControlConflict("database writer control names another writer host")

    monkeypatch.setattr(worker, "reconcile_runtime_control", conflict)
    assert worker.main() == 1
    assert "another writer" in json.loads(capsys.readouterr().out)["runtime_control_error"]

    output = tmp_path / "cli-inventory.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evergarden-worker",
            "inventory",
            "--output",
            str(output),
            "--source-host",
            "test-host",
            "--snapshot-tag",
            "cli-test",
        ],
    )
    assert worker.main() == 0
    assert json.loads(capsys.readouterr().out)["messages"] == 2
    assert json.loads(output.read_text())["scope"] == "mail-only"

    monkeypatch.setattr(
        worker,
        "execute_one",
        lambda job_id, slot: (0, {"job_id": job_id, "scheduled_slot": slot}),
    )
    monkeypatch.setattr(
        sys, "argv", ["evergarden-worker", "due", "--at", "2026-08-17T09:03:00+01:00"]
    )
    assert worker.main() == 0
    assert {item["job_id"] for item in json.loads(capsys.readouterr().out)["jobs"]} == {
        "archive-sync"
    }

    monkeypatch.setattr(sys, "argv", ["evergarden-worker", "run", "cold-export", "--slot", "slot"])
    assert worker.main() == 0
    assert json.loads(capsys.readouterr().out)["job_id"] == "cold-export"
    monkeypatch.setattr(worker, "default_manual_slot", lambda _timezone: "manual-slot")
    monkeypatch.setattr(sys, "argv", ["evergarden-worker", "run", "weekly-rollover"])
    assert worker.main() == 0
    assert json.loads(capsys.readouterr().out)["scheduled_slot"] == "manual-slot"


def test_worker_time_helpers_reject_naive_or_unknown_jobs() -> None:
    # The slot must carry London's current UTC offset; hardcoding +01:00
    # made this fail on every date outside British Summer Time.
    slot = dt.datetime.fromisoformat(worker.default_slot("America/New_York"))
    assert slot.utcoffset() == dt.datetime.now(zoneinfo.ZoneInfo("America/New_York")).utcoffset()
    assert dt.datetime.fromisoformat(worker.default_manual_slot("America/New_York")).second != 0
    parsed = worker.parse_slot("2026-08-17T12:00:00Z")
    assert parsed.tzinfo is not None


def test_take_over_writer_is_a_compare_and_swap_to_this_host(
    tmp_path: Path,
    archive_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = Settings(
        host_id="host-a",
        writer_epoch=3,
        side_effects_enabled=True,
        archive_dir=archive_dir,
        report_dir=tmp_path / "reports",
        database_url="postgresql://unused",
    )
    monkeypatch.setattr(worker, "get_settings", lambda: settings)
    monkeypatch.setattr(worker, "configure_logging", lambda _level: None)
    calls: list[dict] = []
    monkeypatch.setattr(
        worker,
        "transition_runtime_control",
        lambda _url, **kwargs: calls.append(kwargs) or {"active_writer": kwargs["new_writer"]},
    )
    argv = [
        "evergarden-worker",
        "take-over-writer",
        "--expected-writer",
        "host-b",
        "--expected-epoch",
        "2",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert worker.main() == 0
    assert json.loads(capsys.readouterr().out) == {"active_writer": "host-a"}
    assert calls == [
        {
            "expected_writer": "host-b",
            "expected_epoch": 2,
            "expected_side_effects": False,
            "new_writer": "host-a",
            "new_epoch": 3,
            "new_side_effects": True,
        }
    ]

    passive = settings.model_copy(update={"active_writer": "none", "side_effects_enabled": False})
    monkeypatch.setattr(worker, "get_settings", lambda: passive)
    with pytest.raises(RuntimeError, match="name this host"):
        worker.main()


def test_due_evaluates_schedules_in_the_configured_timezone(
    tmp_path: Path,
    archive_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(tmp_path, archive_dir).model_copy(
        update={"schedule_timezone": "Europe/Paris"}
    )
    monkeypatch.setattr(worker, "get_settings", lambda: settings)
    monkeypatch.setattr(worker, "configure_logging", lambda _level: None)
    monkeypatch.setattr(
        worker,
        "execute_one",
        lambda job_id, slot: (0, {"job_id": job_id, "scheduled_slot": slot}),
    )
    monkeypatch.setattr(sys, "argv", ["evergarden-worker", "due", "--at", "2026-08-17T07:05:00Z"])
    assert worker.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["at"] == "2026-08-17T09:05:00+02:00"
    assert output["jobs"] == [
        {"job_id": "oauth-watchdog", "scheduled_slot": "2026-08-17T09:05:00+02:00"}
    ]
