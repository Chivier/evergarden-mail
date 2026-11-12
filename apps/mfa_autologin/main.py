from __future__ import annotations

import argparse
import getpass
import json
import logging
import pathlib
import sys
import tempfile
import time

from evergarden.audit.redaction import configure_logging
from evergarden.auth.credential_store import CredentialStore
from evergarden.auth.mfa_autologin import MicrosoftAutoLogin
from evergarden.auth.provider_oauth import MicrosoftOAuthClient, microsoft_registration
from evergarden.config import get_settings
from evergarden.mail.models import load_account_configs

logger = logging.getLogger(__name__)
INTERVAL_SECONDS = 300


INSPECTION_COMMANDS = frozenset({"status", "disable", "forget"})


def build(*, inspection_only: bool = False) -> MicrosoftAutoLogin:
    """Wire the auto-login service from settings.

    ``inspection_only`` is for ``status``, ``disable`` and ``forget``: they never
    sign in, so they skip the opt-in and app-registration checks. An operator
    who has switched the feature off can always inspect, stop and erase the
    stored password and TOTP seed.
    """
    settings = get_settings()
    if not inspection_only and not settings.mfa_autologin_enabled:
        raise RuntimeError(
            "MFA auto-login is an optional component: set EVERGARDEN_MFA_AUTOLOGIN_ENABLED=true"
        )
    if (
        settings.mode != "production"
        or settings.host_id != settings.active_writer
        or not settings.oauth_callback_enabled
    ):
        raise RuntimeError("MFA auto-login requires the active production credential owner")
    registration = microsoft_registration(settings)
    if not inspection_only:
        if registration.flow != "device_code":
            raise RuntimeError(
                "MFA auto-login drives the device code sign-in: "
                "set EVERGARDEN_MICROSOFT_OAUTH_FLOW=device_code"
            )
        registration.require_configured()
    configure_logging(settings.log_level)
    store = CredentialStore.from_key_file(
        settings.credential_db, key_file=settings.credential_key_file, host_id=settings.host_id
    )
    clients = {
        account.alias: MicrosoftOAuthClient(
            store=store, record_id=account.credential_record, registration=registration
        )
        for account in load_account_configs(settings.account_config_file)
        if account.oauth_provider == "microsoft"
    }
    # Imported lazily: only the browser image ships Playwright.
    from evergarden.auth.microsoft_device_browser import PlaywrightDeviceLogin

    return MicrosoftAutoLogin(
        store=store,
        clients=clients,
        browser_login=PlaywrightDeviceLogin(
            screenshot_dir=settings.report_dir / "mfa-autologin",
            extra_allowed_hosts=settings.mfa_extra_allowed_host_list,
            expected_app_name=registration.app_name,
            locale=settings.mfa_browser_locale,
        ),
    )


def _guarded_step(autologin: MicrosoftAutoLogin, account: str) -> dict:
    """Run one account's step; an unexpected error must not stop the others."""
    try:
        return autologin.step(account)
    except Exception as exc:
        logger.error(
            "MFA auto-login step failed account=%s error_class=%s", account, type(exc).__name__
        )
        return {"account": account, "action": "error", "error_class": type(exc).__name__}


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    enroll = sub.add_parser("enroll", help="store sign-in address, password and TOTP seed")
    enroll.add_argument("account")
    enroll.add_argument(
        "--stdin",
        action="store_true",
        help='read {"username", "password", "totp"} as JSON from standard input',
    )
    sub.add_parser("status")
    disable = sub.add_parser("disable")
    disable.add_argument("account")
    enable = sub.add_parser("enable", help="resume after an automatic stop")
    enable.add_argument("account")
    forget = sub.add_parser("forget", help="erase the stored password and TOTP seed")
    forget.add_argument("account")
    run = sub.add_parser("run")
    run.add_argument("--once", action="store_true")
    run.add_argument("--force", metavar="ACCOUNT", help="sign in now even if the token is healthy")
    args = parser.parse_args()
    autologin = build(inspection_only=args.command in INSPECTION_COMMANDS)
    if args.command == "enroll":
        if args.stdin:
            # Secrets arrive on stdin so they never appear in argv or the
            # container's environment.
            supplied = json.loads(sys.stdin.read())
            username = str(supplied["username"]).strip()
            password = str(supplied["password"])
            secret = str(supplied["totp"])
        else:
            username = input("Microsoft sign-in address: ").strip()
            password = getpass.getpass("Password (hidden): ")
            secret = getpass.getpass("TOTP secret, base32 or otpauth:// URI (hidden): ")
        autologin.enroll(args.account, username=username, password=password, totp_secret=secret)
        print(json.dumps(autologin.status(args.account)))
        return 0
    if args.command == "status":
        print(json.dumps([autologin.status(account) for account in autologin.clients], indent=2))
        return 0
    if args.command == "disable":
        autologin._update(args.account, disabled_reason="disabled by administrator")
        print(json.dumps(autologin.status(args.account)))
        return 0
    if args.command == "enable":
        autologin.enable(args.account)
        print(json.dumps(autologin.status(args.account)))
        return 0
    if args.command == "forget":
        autologin.forget(args.account)
        print(json.dumps(autologin.status(args.account)))
        return 0
    if args.force:
        report = autologin.step(args.force, force=True)
        print(json.dumps(report))
        return 0 if report["action"] == "reauthorized" else 1
    heartbeat = pathlib.Path(tempfile.gettempdir()) / "mfa-autologin-heartbeat"
    while True:
        reports = [_guarded_step(autologin, account) for account in autologin.clients]
        # A persistent unexpected error leaves the heartbeat stale, so the
        # container turns unhealthy instead of the loop dying.
        if not any(item["action"] == "error" for item in reports):
            heartbeat.touch(mode=0o600)
        # Disabled and backing-off accounts were logged when they got there.
        quiet = {"healthy", "not-enrolled", "disabled", "backing-off"}
        acted = [item for item in reports if item["action"] not in quiet]
        if args.once:
            print(json.dumps(reports))
            return 0
        if acted:
            logger.info("MFA auto-login result=%s", json.dumps(acted))
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
