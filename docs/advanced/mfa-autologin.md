# Optional: Microsoft MFA auto-login

Some organisations make Microsoft accounts sign in again interactively every
few days or weeks (a sign-in frequency policy). Each time, Evergarden stops
syncing that mailbox until you connect it again. The optional `mfa-autologin`
service answers those prompts for you: it stores the account's password and
TOTP seed and signs in through Microsoft's device-code page in a headless
Chromium browser.

## Read this first

- **It collapses two factors into one.** The password and the TOTP seed live
  together in the encrypted credential store. Anyone who obtains the store and
  `.local/run/credential_store_key` can sign in as the account, MFA included.
- **It may break your organisation's rules.** Many sign-in policies forbid
  storing a second factor next to the password or automating sign-in. Check
  before you enable it.
- It is off by default and is not needed for normal use. Without it you simply
  reconnect the mailbox when Microsoft asks.

## How it behaves

- Every five minutes it checks each enrolled Microsoft mailbox and acts only
  when the stored token can no longer be refreshed.
- It drives only Microsoft's own sign-in pages, plus identity-provider hosts
  you list in `EVERGARDEN_MFA_EXTRA_ALLOWED_HOSTS` (for a federated sign-in
  page such as an organisation's ADFS). Any other host or an unknown page stops
  the attempt and leaves a screenshot in `.local/data/reports/mfa-autologin/`.
- It approves the device-code prompt only for the app named in
  `EVERGARDEN_MICROSOFT_OAUTH_APP_NAME`.
- After a failure it waits 30 minutes, doubling up to 12 hours. After three
  failures in a row, or at once when Microsoft or the identity provider rejects
  the password or code, it disables itself for that mailbox, so it cannot lock
  the account. It never reuses a TOTP time window.
- The page text is matched in English; `EVERGARDEN_MFA_BROWSER_LOCALE`
  (default `en-US`) sets the browser language.

## Requirements

In `.local/run/runtime.env`:

```dotenv
EVERGARDEN_MFA_AUTOLOGIN_ENABLED=true
EVERGARDEN_MICROSOFT_OAUTH_FLOW=device_code
EVERGARDEN_MICROSOFT_OAUTH_APP_NAME=<your Entra app's display name>
# Only for a federated sign-in page, comma-separated:
EVERGARDEN_MFA_EXTRA_ALLOWED_HOSTS=adfs.example.com
# The service runs only on a host with provider writes enabled:
EVERGARDEN_SIDE_EFFECTS_ENABLED=true
```

In `.env`, add the profile, for example
`COMPOSE_PROFILES=scheduler,mfa-autologin`. The service uses a separate image
(`EVERGARDEN_AUTOLOGIN_IMAGE`) with Chromium added; `docker compose up -d
--build` builds it.

The Entra app must allow public client flows (see
[providers.md](../providers.md#register-the-app)), and the mailbox must already
be connected once.

## Enroll an account

The TOTP seed is the secret behind the authenticator QR code: when you add an
authenticator app method to the Microsoft account, choose "Can't scan the QR
code?" to see it. Enter it as base32 or as the `otpauth://` URI.

```bash
docker compose run --rm mfa-autologin python -m apps.mfa_autologin.main enroll work
```

It prompts for the sign-in address, the password and the TOTP seed without
echoing them. Never pass them as arguments or environment variables.

For re-enrolment without typing, keep the values in `.local/run/mfa-autologin.json`
(mode 0600, not mounted into any container):

```json
{"work": {"username": "you@example.com", "password": "...", "totp": "otpauth://..."}}
```

and run `python3 deploy/scripts/enroll_mfa_autologin.py [ALIAS ...]`, which
pipes each entry to the container on standard input. Run it again after a
password change.

## Operate

```bash
docker compose run --rm mfa-autologin python -m apps.mfa_autologin.main status
docker compose run --rm mfa-autologin python -m apps.mfa_autologin.main run --once --force work   # test now
docker compose run --rm mfa-autologin python -m apps.mfa_autologin.main disable work
docker compose run --rm mfa-autologin python -m apps.mfa_autologin.main enable work    # after an automatic stop
docker compose run --rm mfa-autologin python -m apps.mfa_autologin.main forget work    # erase password and seed
docker compose up -d mfa-autologin                                                     # start the background service
```

`status`, `disable` and `forget` work even after you switch the feature off.
If the seed may have leaked, run `forget` and also remove that authenticator
method from the Microsoft account.
