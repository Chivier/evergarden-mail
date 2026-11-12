"""Drive Microsoft's device-code sign-in pages in headless Chromium.

Microsoft's markup changes without notice, so each page is recognised by a few
stable form field names and the driver acts on whichever page is showing. An
unrecognised page fails closed and leaves a private screenshot for diagnosis.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import logging
import os
import re
from pathlib import Path

from evergarden.auth.mfa_autologin import AutoLoginError, AutoLoginRejected, LoginCredentials

logger = logging.getLogger(__name__)

PAGE_TIMEOUT_MS = 30_000
TOTAL_SECONDS = 180
# Microsoft's own sign-in hosts. A federated tenant hands the password step to
# its organisation's identity provider (for example ADFS) before returning for
# the second factor; those hosts are added by EVERGARDEN_MFA_EXTRA_ALLOWED_HOSTS.
ALLOWED_HOSTS = (
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.live.com",
    "microsoft.com",
    "www.microsoft.com",
    "aadcdn.msauth.net",
)
SUBMIT_SELECTORS = (
    "#idSIButton9",
    "#idSubmit_SAOTCC_Continue",
    "button[type=submit]",
    "input[type=submit]",
)
SUCCESS_TEXT = re.compile(
    r"(you have signed in to|you may now close this window|已登录|现在可以关闭此窗口)", re.I
)
REJECTED_TEXT = re.compile(
    r"(your account or password is incorrect|password is incorrect|"
    r"account has been locked|account is locked|you didn't enter the expected verification code|"
    r"that code didn't work|this doesn't look like a valid code|"
    r"incorrect user id or password)",
    re.I,
)
EXPIRED_CODE_TEXT = re.compile(r"(code (?:has )?expired|code you entered has expired)", re.I)
# Microsoft's device-code phishing guard ("Approve sign-in on another device").
REMOTE_APPROVAL_TEXT = re.compile(r"approve sign[- ]in on another device", re.I)
REMOTE_APPROVAL_APP = re.compile(r"signing in to\s+(.+?)\s+on a remote device", re.I | re.S)
# Matched by exact text only: the focused default on this page is "This wasn't me".
APPROVE_SELECTORS = (
    "input[type=submit][value='Approve']",
    "input[type=button][value='Approve']",
    "button:text-is('Approve')",
)


class PlaywrightDeviceLogin:
    def __init__(
        self,
        *,
        screenshot_dir: Path | None = None,
        headless: bool = True,
        extra_allowed_hosts: tuple[str, ...] = (),
        expected_app_name: str = "",
        locale: str = "en-US",
    ):
        self.screenshot_dir = screenshot_dir
        self.headless = headless
        # Hosts the browser may visit: Microsoft's plus the deployment's
        # federated identity providers.
        self.allowed_hosts = ALLOWED_HOSTS + tuple(host.casefold() for host in extra_allowed_hosts)
        # The registered app's display name; the remote-device approval is only
        # given for a sign-in that names it.
        self.expected_app_name = expected_app_name.strip().casefold()
        self.locale = locale

    def _screenshot(self, page, label: str) -> None:
        if self.screenshot_dir is None:
            return
        self.screenshot_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        path = self.screenshot_dir / f"{stamp}-{label}.png"
        try:
            page.screenshot(path=str(path), full_page=True)
            os.chmod(path, 0o600)
            logger.warning("MFA auto-login saved a diagnostic screenshot path=%s", path)
        except Exception:
            logger.warning("MFA auto-login could not save a diagnostic screenshot")

    @staticmethod
    def _visible(page, selector: str) -> bool:
        locator = page.locator(selector)
        return locator.count() > 0 and locator.first.is_visible()

    def _submit(self, page) -> None:
        for selector in SUBMIT_SELECTORS:
            if self._visible(page, selector):
                page.locator(selector).first.click()
                return
        page.keyboard.press("Enter")

    def _settle(self, page) -> None:
        # Microsoft's pages keep telemetry requests open; an idle network is a
        # hint, not a requirement.
        with contextlib.suppress(Exception):
            page.wait_for_load_state("networkidle", timeout=10_000)
        page.wait_for_timeout(1_500)

    def __call__(
        self, *, verification_uri: str, user_code: str, credentials: LoginCredentials
    ) -> None:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=self.headless, args=["--disable-dev-shm-usage"]
            )
            try:
                context = browser.new_context(locale=self.locale)
                page = context.new_page()
                page.set_default_timeout(PAGE_TIMEOUT_MS)
                try:
                    self._drive(page, verification_uri, user_code, credentials)
                except AutoLoginError:
                    self._screenshot(page, "failed")
                    raise
                except Exception as exc:
                    self._screenshot(page, "error")
                    raise AutoLoginError(
                        f"browser automation failed: {type(exc).__name__}"
                    ) from exc
            finally:
                browser.close()

    def _drive(self, page, verification_uri: str, user_code: str, creds: LoginCredentials) -> None:
        page.goto(verification_uri)
        deadline = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=TOTAL_SECONDS)
        done: set[str] = set()
        idle_rounds = 0
        while dt.datetime.now(dt.UTC) < deadline:
            self._settle(page)
            host = page.url.split("/")[2] if "://" in page.url else ""
            if not any(host == item or host.endswith("." + item) for item in self.allowed_hosts):
                raise AutoLoginError(
                    f"sign-in left Microsoft for an unsupported host: {host} "
                    "(a federated identity provider must be listed in "
                    "EVERGARDEN_MFA_EXTRA_ALLOWED_HOSTS)"
                )
            text = page.inner_text("body")
            if SUCCESS_TEXT.search(text):
                return
            if REJECTED_TEXT.search(text):
                raise AutoLoginRejected(REJECTED_TEXT.search(text).group(1))
            if EXPIRED_CODE_TEXT.search(text):
                raise AutoLoginError("Microsoft reported the device code as expired")
            acted = self._act(page, text, user_code, creds, done)
            idle_rounds = 0 if acted else idle_rounds + 1
            if idle_rounds >= 5:
                raise AutoLoginError("Microsoft showed a sign-in page the driver does not know")
        raise AutoLoginError("Microsoft sign-in did not finish in time")

    def _act(self, page, text: str, user_code: str, creds: LoginCredentials, done: set) -> bool:
        # Device code entry. Microsoft names both this field and the TOTP field
        # "otc", so the TOTP page is told apart by its own identifiers below.
        if "device-code" not in done and self._visible(page, "input#otc"):
            page.fill("input#otc", user_code)
            self._submit(page)
            done.add("device-code")
            return True
        if self._visible(page, "input[name=loginfmt]") and "username" not in done:
            page.fill("input[name=loginfmt]", creds.username)
            self._submit(page)
            done.add("username")
            return True
        if self._visible(page, "input[name=passwd]"):
            if "password" in done:
                raise AutoLoginRejected("Microsoft asked for the password a second time")
            page.fill("input[name=passwd]", creds.password)
            self._submit(page)
            done.add("password")
            return True
        # ADFS sign-in form of a federated tenant.
        if self._visible(page, "#passwordInput"):
            if "password" in done:
                raise AutoLoginRejected("ADFS asked for the password a second time")
            if not page.input_value("#userNameInput"):
                page.fill("#userNameInput", creds.username)
            page.fill("#passwordInput", creds.password)
            page.locator("#submitButton").first.click()
            done.add("password")
            return True
        totp_field = next(
            (
                selector
                for selector in (
                    "#idTxtBx_SAOTCC_OTC",
                    "input[name=otc][autocomplete=one-time-code]",
                    "#verificationCodeInput",
                    "input[autocomplete=one-time-code]",
                )
                if self._visible(page, selector)
            ),
            None,
        )
        if totp_field:
            # One fresh code may be retried once (clock skew); a second
            # rejection means the stored seed is wrong.
            if "totp-retry" in done:
                raise AutoLoginRejected("Microsoft rejected two verification codes")
            page.fill(totp_field, creds.next_totp())
            self._submit(page)
            done.add("totp-retry" if "totp" in done else "totp")
            return True
        # Push notification or SMS offered first: switch to the authenticator code.
        for selector in (
            "#signInAnotherWay",
            "a:has-text('I can\\'t use my Microsoft Authenticator')",
        ):
            if "other-way" not in done and self._visible(page, selector):
                page.locator(selector).first.click()
                done.add("other-way")
                return True
        for selector in (
            "div[data-value=PhoneAppOTP]",
            "[role=button]:has-text('Use a verification code')",
        ):
            if self._visible(page, selector):
                page.locator(selector).first.click()
                return True
        if REMOTE_APPROVAL_TEXT.search(text):
            return self._approve_own_device_sign_in(page, text, done)
        # "Are you trying to sign in to ...?" application confirmation.
        if re.search(r"are you trying to sign in to", text, re.I):
            self._submit(page)
            return True
        # "Stay signed in?" This browser profile is discarded, so decline.
        if self._visible(page, "#idBtn_Back") and re.search(r"stay signed in", text, re.I):
            page.click("#idBtn_Back")
            return True
        # An already-known account offered in a picker.
        tile = f"[data-test-id='{creds.username}'], div[role=button]:has-text('{creds.username}')"
        if self._visible(page, tile):
            page.locator(tile).first.click()
            return True
        return False

    def _approve_own_device_sign_in(self, page, text: str, done: set) -> bool:
        """Approve the remote-device warning only for the sign-in this session started.

        The warning protects against approving a device code someone else sent
        you. Here the code was requested by Evergarden itself moments ago and
        typed into this same browser session, so approving is safe exactly when
        that code entry happened and the named application is our own client.
        """
        if "device-code" not in done:
            raise AutoLoginError(
                "Microsoft asked to approve a device sign-in this session did not start"
            )
        if not self.expected_app_name:
            raise AutoLoginError(
                "Microsoft asked to approve a device sign-in; set "
                "EVERGARDEN_MICROSOFT_OAUTH_APP_NAME to the app's display name to allow it"
            )
        match = REMOTE_APPROVAL_APP.search(text)
        app = match.group(1).strip().casefold() if match else ""
        if self.expected_app_name not in app:
            raise AutoLoginError("Microsoft asked to approve a device sign-in for another app")
        if "remote-approval" in done:
            raise AutoLoginError("Microsoft asked to approve the device sign-in twice")
        for selector in APPROVE_SELECTORS:
            if self._visible(page, selector):
                page.locator(selector).first.click()
                done.add("remote-approval")
                logger.info("MFA auto-login approved its own device sign-in")
                return True
        raise AutoLoginError("Microsoft's device sign-in approval button was not found")
