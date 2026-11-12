from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from evergarden.auth import microsoft_device_browser as browser_module
from evergarden.auth.mfa_autologin import AutoLoginError, AutoLoginRejected, LoginCredentials
from evergarden.auth.microsoft_device_browser import PlaywrightDeviceLogin

DEVICE = "https://login.microsoftonline.com/common/oauth2/deviceauth"
ADFS_HOST = "adfs.university.example"
ADFS = f"https://{ADFS_HOST}/adfs/ls/"
APP = "Example Mail"


class Screen:
    def __init__(self, url: str, text: str = "", visible=(), values=None):
        self.url = url
        self.text = text
        self.visible = set(visible)
        self.values = dict(values or {})


class FakeLocator:
    def __init__(self, page: FakePage, selector: str):
        self.page = page
        self.selector = selector

    def count(self) -> int:
        return int(self.selector in self.page.screen.visible)

    @property
    def first(self) -> FakeLocator:
        return self

    def is_visible(self) -> bool:
        return self.selector in self.page.screen.visible

    def click(self) -> None:
        self.page.actions.append(("click", self.selector))
        self.page.advance()


class FakeKeyboard:
    def __init__(self, page: FakePage):
        self.page = page

    def press(self, key: str) -> None:
        self.page.actions.append(("press", key))
        self.page.advance()


class FakePage:
    """Each click or Enter moves to the next scripted screen."""

    def __init__(self, screens: list[Screen]):
        self.screens = screens
        self.index = 0
        self.actions: list[tuple] = []
        self.keyboard = FakeKeyboard(self)

    @property
    def screen(self) -> Screen:
        return self.screens[min(self.index, len(self.screens) - 1)]

    @property
    def url(self) -> str:
        return self.screen.url

    def advance(self) -> None:
        self.index += 1

    def goto(self, url: str) -> None:
        self.actions.append(("goto", url))

    def inner_text(self, _selector: str) -> str:
        return self.screen.text

    def locator(self, selector: str) -> FakeLocator:
        return FakeLocator(self, selector)

    def fill(self, selector: str, value: str) -> None:
        self.actions.append(("fill", selector, value))

    def click(self, selector: str) -> None:
        self.locator(selector).click()

    def input_value(self, selector: str) -> str:
        return self.screen.values.get(selector, "")

    def wait_for_load_state(self, *_args, **_kwargs) -> None:
        raise TimeoutError("telemetry kept the network busy")

    def wait_for_timeout(self, _ms: int) -> None:
        return None

    def screenshot(self, *, path: str, full_page: bool) -> None:
        Path(path).write_bytes(b"png")

    def set_default_timeout(self, _ms: int) -> None:
        return None


def _credentials() -> LoginCredentials:
    codes = iter(["111111", "222222", "333333"])
    return LoginCredentials(
        username="user@example.test", password="pw", next_totp=lambda: next(codes)
    )


def _drive(screens: list[Screen]) -> FakePage:
    page = FakePage(screens)
    PlaywrightDeviceLogin(extra_allowed_hosts=(ADFS_HOST,), expected_app_name=APP)._drive(
        page, DEVICE, "ABCD1234", _credentials()
    )
    return page


def test_driver_completes_the_federated_device_sign_in() -> None:
    page = _drive(
        [
            Screen(DEVICE, "Enter code", {"input#otc", "#idSIButton9"}),
            Screen(DEVICE, "Are you trying to sign in to Example Mail?", {"#idSIButton9"}),
            Screen(DEVICE, "Sign in", {"input[name=loginfmt]", "button[type=submit]"}),
            Screen(ADFS, "Sign in", {"#passwordInput"}, {"#userNameInput": ""}),
            Screen(DEVICE, "Approve sign in request", {"#signInAnotherWay"}),
            Screen(DEVICE, "Verify your identity", {"div[data-value=PhoneAppOTP]"}),
            Screen(DEVICE, "Enter code", {"#idTxtBx_SAOTCC_OTC", "#idSubmit_SAOTCC_Continue"}),
            Screen(DEVICE, "Stay signed in?", {"#idBtn_Back"}),
            Screen(DEVICE, "You have signed in to the Example Mail application"),
        ]
    )
    fills = [action[1:] for action in page.actions if action[0] == "fill"]
    assert fills == [
        ("input#otc", "ABCD1234"),
        ("input[name=loginfmt]", "user@example.test"),
        ("#userNameInput", "user@example.test"),
        ("#passwordInput", "pw"),
        ("#idTxtBx_SAOTCC_OTC", "111111"),
    ]
    assert ("click", "#idBtn_Back") in page.actions
    assert ("click", "#submitButton") in page.actions


def test_driver_handles_password_page_tiles_and_enter_fallback() -> None:
    page = _drive(
        [
            Screen(
                DEVICE,
                "Pick an account",
                {
                    "[data-test-id='user@example.test'], "
                    "div[role=button]:has-text('user@example.test')"
                },
            ),
            Screen(DEVICE, "Enter password", {"input[name=passwd]"}),
            Screen(DEVICE, "Enter code", {"input[name=otc][autocomplete=one-time-code]"}),
            Screen(DEVICE, "You may now close this window"),
        ]
    )
    assert ("press", "Enter") in page.actions
    assert ("fill", "input[name=passwd]", "pw") in page.actions


@pytest.mark.parametrize(
    ("screens", "error", "message"),
    [
        (
            [Screen(ADFS, "Incorrect user ID or password. Type the correct user ID and password.")],
            AutoLoginRejected,
            "(?i)incorrect user id or password",
        ),
        ([Screen("https://evil.example/login", "Sign in")], AutoLoginError, "unsupported host"),
        ([Screen(DEVICE, "That code has expired")], AutoLoginError, "expired"),
        ([Screen(DEVICE, "Something new")], AutoLoginError, "does not know"),
        (
            [
                Screen(DEVICE, "Enter password", {"input[name=passwd]"}),
                Screen(DEVICE, "Enter password", {"input[name=passwd]"}),
            ],
            AutoLoginRejected,
            "password a second time",
        ),
        (
            [
                Screen(ADFS, "Sign in", {"#passwordInput"}, {"#userNameInput": "x"}),
                Screen(ADFS, "Sign in", {"#passwordInput"}, {"#userNameInput": "x"}),
            ],
            AutoLoginRejected,
            "password a second time",
        ),
        (
            [Screen(DEVICE, "Enter code", {"#idTxtBx_SAOTCC_OTC"})] * 3,
            AutoLoginRejected,
            "two verification codes",
        ),
    ],
)
def test_driver_fails_closed(screens, error, message) -> None:
    with pytest.raises(error, match=message):
        _drive(screens)


def test_driver_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(browser_module, "TOTAL_SECONDS", -1)
    with pytest.raises(AutoLoginError, match="did not finish in time"):
        _drive([Screen(DEVICE, "Enter code", {"input#otc"})])


def _fake_playwright(
    monkeypatch: pytest.MonkeyPatch, page: FakePage, contexts: list[dict] | None = None
) -> list[str]:
    events: list[str] = []

    class Browser:
        def new_context(self, **kwargs):
            if contexts is not None:
                contexts.append(kwargs)
            return types.SimpleNamespace(new_page=lambda: page)

        def close(self):
            events.append("closed")

    class Manager:
        chromium = types.SimpleNamespace(launch=lambda **_kwargs: Browser())

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    module = types.ModuleType("playwright.sync_api")
    module.sync_playwright = Manager
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", module)
    return events


def test_browser_session_succeeds_and_always_closes(monkeypatch, tmp_path: Path) -> None:
    page = FakePage([Screen(DEVICE, "You have signed in to the application")])
    events = _fake_playwright(monkeypatch, page)
    PlaywrightDeviceLogin(screenshot_dir=tmp_path)(
        verification_uri=DEVICE, user_code="ABCD1234", credentials=_credentials()
    )
    assert events == ["closed"]
    assert list(tmp_path.iterdir()) == []


def test_browser_failures_leave_a_private_screenshot(monkeypatch, tmp_path: Path) -> None:
    page = FakePage([Screen(DEVICE, "Something new")])
    events = _fake_playwright(monkeypatch, page)
    with pytest.raises(AutoLoginError):
        PlaywrightDeviceLogin(screenshot_dir=tmp_path / "shots")(
            verification_uri=DEVICE, user_code="ABCD1234", credentials=_credentials()
        )
    shots = list((tmp_path / "shots").iterdir())
    assert len(shots) == 1 and shots[0].name.endswith("-failed.png")
    assert shots[0].stat().st_mode & 0o777 == 0o600
    assert events == ["closed"]

    def broken_goto(_url):
        raise RuntimeError("navigation crashed")

    page.goto = broken_goto
    with pytest.raises(AutoLoginError, match="RuntimeError"):
        PlaywrightDeviceLogin()(
            verification_uri=DEVICE, user_code="ABCD1234", credentials=_credentials()
        )

    def broken_screenshot(**_kwargs):
        raise OSError("disk full")

    page.screenshot = broken_screenshot
    with pytest.raises(AutoLoginError):
        PlaywrightDeviceLogin(screenshot_dir=tmp_path / "shots")(
            verification_uri=DEVICE, user_code="ABCD1234", credentials=_credentials()
        )


REMOTE_TEXT = (
    "Approve sign-in on another device\nYou're signing in to Example Mail on a remote device "
    "located in SPRINGFIELD, United States using your university.example account.\n"
    "Approve\nThis wasn't me"
)
APPROVE = "input[type=submit][value='Approve']"


def test_driver_approves_the_remote_device_warning_for_its_own_code() -> None:
    page = _drive(
        [
            Screen(DEVICE, "Enter code", {"input#otc", "#idSIButton9"}),
            Screen(DEVICE, REMOTE_TEXT, {APPROVE, "#idSIButton9"}),
            Screen(DEVICE, "You have signed in to the Example Mail application"),
        ]
    )
    assert ("click", APPROVE) in page.actions
    # Never the generic submit, which may be "This wasn't me".
    assert page.actions.count(("click", "#idSIButton9")) == 1


@pytest.mark.parametrize(
    ("screens", "message"),
    [
        # The warning without this session having entered a code: fail closed.
        ([Screen(DEVICE, REMOTE_TEXT, {APPROVE})], "did not start"),
        (
            [
                Screen(DEVICE, "Enter code", {"input#otc"}),
                Screen(DEVICE, REMOTE_TEXT.replace(APP, "Evil App"), {APPROVE}),
            ],
            "another app",
        ),
        (
            [
                Screen(DEVICE, "Enter code", {"input#otc"}),
                Screen(DEVICE, REMOTE_TEXT, {APPROVE}),
                Screen(DEVICE, REMOTE_TEXT, {APPROVE}),
            ],
            "twice",
        ),
        (
            [Screen(DEVICE, "Enter code", {"input#otc"}), Screen(DEVICE, REMOTE_TEXT, set())],
            "button was not found",
        ),
    ],
)
def test_driver_refuses_remote_device_approval_it_cannot_prove(screens, message) -> None:
    with pytest.raises(AutoLoginError, match=message):
        _drive(screens)


def test_federated_identity_provider_must_be_configured() -> None:
    page = FakePage([Screen(ADFS, "Sign in", {"#passwordInput"})])
    with pytest.raises(AutoLoginError, match="EVERGARDEN_MFA_EXTRA_ALLOWED_HOSTS"):
        PlaywrightDeviceLogin(expected_app_name=APP)._drive(
            page, DEVICE, "ABCD1234", _credentials()
        )
    # Subdomains of a configured host are allowed, look-alikes are not.
    sub = FakePage([Screen(f"https://sts.{ADFS_HOST}/", "You may now close this window")])
    PlaywrightDeviceLogin(extra_allowed_hosts=(ADFS_HOST.upper(),))._drive(
        sub, DEVICE, "ABCD1234", _credentials()
    )
    lookalike = FakePage([Screen(f"https://evil-{ADFS_HOST}/", "Sign in")])
    with pytest.raises(AutoLoginError, match="unsupported host"):
        PlaywrightDeviceLogin(extra_allowed_hosts=(ADFS_HOST,))._drive(
            lookalike, DEVICE, "ABCD1234", _credentials()
        )


def test_remote_device_approval_needs_a_declared_app_name() -> None:
    page = FakePage(
        [
            Screen(DEVICE, "Enter code", {"input#otc"}),
            Screen(DEVICE, REMOTE_TEXT, {APPROVE}),
        ]
    )
    with pytest.raises(AutoLoginError, match="EVERGARDEN_MICROSOFT_OAUTH_APP_NAME"):
        PlaywrightDeviceLogin()._drive(page, DEVICE, "ABCD1234", _credentials())
    assert ("click", APPROVE) not in page.actions


def test_browser_uses_the_configured_locale(monkeypatch) -> None:
    page = FakePage([Screen(DEVICE, "You have signed in to the application")])
    contexts: list[dict] = []
    _fake_playwright(monkeypatch, page, contexts)
    PlaywrightDeviceLogin(locale="en-GB")(
        verification_uri=DEVICE, user_code="ABCD1234", credentials=_credentials()
    )
    PlaywrightDeviceLogin()(
        verification_uri=DEVICE, user_code="ABCD1234", credentials=_credentials()
    )
    assert [item["locale"] for item in contexts] == ["en-GB", "en-US"]
