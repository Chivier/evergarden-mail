from __future__ import annotations

import pytest
from pydantic import ValidationError

from evergarden.config import Settings


def test_identity_settings_default_to_generic_and_disabled() -> None:
    settings = Settings()
    assert settings.microsoft_oauth_flow == "authorization_code"
    assert settings.microsoft_oauth_app_name == ""
    assert settings.mfa_autologin_enabled is False
    assert settings.mfa_extra_allowed_host_list == ()
    assert settings.mfa_browser_locale == "en-US"


def test_identity_settings_read_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVERGARDEN_MICROSOFT_OAUTH_FLOW", "device_code")
    monkeypatch.setenv("EVERGARDEN_MICROSOFT_OAUTH_APP_NAME", "Example Mail")
    monkeypatch.setenv("EVERGARDEN_MFA_AUTOLOGIN_ENABLED", "true")
    monkeypatch.setenv(
        "EVERGARDEN_MFA_EXTRA_ALLOWED_HOSTS", " ADFS.University.Example, sts.company.example ,"
    )
    monkeypatch.setenv("EVERGARDEN_MFA_BROWSER_LOCALE", "en-GB")
    settings = Settings()
    assert settings.microsoft_oauth_flow == "device_code"
    assert settings.microsoft_oauth_app_name == "Example Mail"
    assert settings.mfa_autologin_enabled is True
    assert settings.mfa_extra_allowed_host_list == (
        "adfs.university.example",
        "sts.company.example",
    )
    assert settings.mfa_browser_locale == "en-GB"


@pytest.mark.parametrize(
    "values",
    [
        {"microsoft_oauth_flow": "implicit"},
        {"microsoft_oauth_app_name": "Example\nMail"},
        {"microsoft_oauth_app_name": "x" * 121},
        {"mfa_extra_allowed_hosts": "https://adfs.university.example"},
        {"mfa_extra_allowed_hosts": "*.university.example"},
        {"mfa_extra_allowed_hosts": "localhost"},
        {"mfa_browser_locale": "en_GB"},
        {"mfa_browser_locale": "english"},
    ],
)
def test_identity_settings_reject_malformed_values(values: dict) -> None:
    with pytest.raises(ValidationError):
        Settings(**values)
