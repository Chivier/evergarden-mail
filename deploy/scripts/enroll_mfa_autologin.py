"""Enroll MFA auto-login accounts from the private source file without echoing secrets.

`.local/run/mfa-autologin.json` maps a mail account alias to its Microsoft sign-in:

    {"work": {"username": "user@example.test", "password": "...", "totp": "otpauth://..."}}

`totp` is a base32 seed or the authenticator's otpauth:// URI. The file stays on the
host (mode 0600, mounted into no container). Each entry is piped to
`apps.mfa_autologin.main enroll --stdin`, which stores it in the encrypted
credential store. Rerun after changing a password.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import stat
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / ".local" / "run" / "mfa-autologin.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("accounts", nargs="*", help="aliases to enroll (default: all in the file)")
    parser.add_argument("--source", type=pathlib.Path, default=SOURCE)
    args = parser.parse_args()
    if args.source.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(f"{args.source} must be private: chmod 600", file=sys.stderr)
        return 2
    entries = json.loads(args.source.read_text())
    unknown = sorted(set(args.accounts) - set(entries))
    if unknown:
        print(f"not in {args.source}: {', '.join(unknown)}", file=sys.stderr)
        return 2
    status = 0
    for account in args.accounts or sorted(entries):
        entry = entries[account]
        missing = [key for key in ("username", "password", "totp") if not entry.get(key)]
        if missing:
            print(f"{account}: missing {', '.join(missing)}", file=sys.stderr)
            status = 2
            continue
        command = [
            "docker",
            "compose",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "mfa-autologin",
            "python",
            "-m",
            "apps.mfa_autologin.main",
            "enroll",
            account,
            "--stdin",
        ]
        result = subprocess.run(  # noqa: S603 - fixed argv; secrets travel on stdin
            command, input=json.dumps(entry), text=True, cwd=ROOT, check=False
        )
        status = status or result.returncode
    return status


if __name__ == "__main__":
    raise SystemExit(main())
