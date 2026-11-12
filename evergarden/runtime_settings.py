"""Private, validated overrides for application environment settings.

The web process can edit only these fields. Infrastructure identity, database
access, secret paths and web/auth feature gates stay under operator control.
Every process reads the same file at startup, including one-shot workers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from evergarden.private_json import PrivateJsonStore, canonical, revision

if TYPE_CHECKING:
    from evergarden.config import Settings

# group, input kind, optional choices. Labels/help live in the UI catalogues.
EDITABLE_SETTINGS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "admin_login_max_failures": ("security", "number", ()),
    "admin_login_window_seconds": ("security", "number", ()),
    "admin_session_ttl_seconds": ("security", "number", ()),
    "schedule_timezone": ("general", "text", ()),
    "log_level": ("general", "select", ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")),
    "approval_draft_lifetime_hours": ("writes", "number", ()),
    "approval_dispatch_parallel": ("writes", "number", ()),
    "side_effects_enabled": ("writes", "checkbox", ()),
    "trash_actions_enabled": ("writes", "checkbox", ()),
    "approval_dispatch_enabled": ("writes", "checkbox", ()),
    "auto_approve": ("writes", "text", ()),
    "uidplus_move_accounts": ("writes", "text", ()),
    "thunderbird_bridge_accounts": ("writes", "text", ()),
    "microsoft_oauth_client_id": ("oauth", "text", ()),
    "microsoft_oauth_tenant": ("oauth", "text", ()),
    "microsoft_oauth_redirect_uri": ("oauth", "url", ()),
    "microsoft_oauth_flow": ("oauth", "select", ("authorization_code", "device_code")),
    "microsoft_oauth_app_name": ("oauth", "text", ()),
    "google_oauth_redirect_uri": ("oauth", "url", ()),
    "mfa_autologin_enabled": ("oauth", "checkbox", ()),
    "mfa_extra_allowed_hosts": ("oauth", "text", ()),
    "mfa_browser_locale": ("oauth", "text", ()),
}
RISK_SETTINGS = frozenset(
    {
        "side_effects_enabled",
        "trash_actions_enabled",
        "auto_approve",
        "uidplus_move_accounts",
        "thunderbird_bridge_accounts",
        "mfa_autologin_enabled",
    }
)


class RuntimeSettingsError(RuntimeError):
    pass


class RuntimeSettingsConflict(RuntimeSettingsError):
    pass


class RuntimeSettingsManager:
    def __init__(self, current: Settings):
        if current.account_config_file is None:
            raise RuntimeSettingsError("settings require a private account configuration directory")
        self.current = current
        self.store = PrivateJsonStore(
            current.account_config_file.with_name("runtime-settings.json"),
            label="runtime settings",
            error_type=RuntimeSettingsError,
        )

    def _read(self) -> dict[str, Any]:
        value = self.store.read_json(
            max_bytes=32 * 1024,
            default={"schema_version": 1, "values": {}},
        )
        if (
            set(value) != {"schema_version", "values"}
            or value["schema_version"] != 1
            or not isinstance(value["values"], dict)
        ):
            raise RuntimeSettingsError("runtime settings document is malformed")
        self._validate(value["values"])
        return value

    def _validate(self, values: dict[str, Any]) -> Settings:
        from evergarden.config import Settings

        for name, value in values.items():
            if name not in EDITABLE_SETTINGS:
                raise RuntimeSettingsError("setting is managed outside the web interface")
            kind = EDITABLE_SETTINGS[name][1]
            expected_type = bool if kind == "checkbox" else int if kind == "number" else str
            if type(value) is not expected_type or (
                isinstance(value, str) and (len(value) > 4096 or any(c in value for c in "\r\n\0"))
            ):
                raise RuntimeSettingsError(f"invalid value for EVERGARDEN_{name.upper()}")
            choices = EDITABLE_SETTINGS[name][2]
            if choices and value not in choices:
                raise RuntimeSettingsError(f"invalid choice for EVERGARDEN_{name.upper()}")
        try:
            return Settings(**{**self.current.model_dump(), **values})
        except ValidationError as exc:
            # Pydantic errors can include the whole settings document. Return
            # field names only, never values or the process environment.
            fields = sorted({str(e["loc"][0]) for e in exc.errors() if e["loc"]})
            raise RuntimeSettingsError(
                "invalid settings combination" + (f": {', '.join(fields)}" if fields else "")
            ) from exc

    def configured(self) -> Settings:
        # Readers have a read-only mount. Atomic replacement makes a lock file
        # unnecessary here; only the single web writer needs the exclusive lock.
        return self._validate(self._read()["values"])

    def _public(self, value: dict[str, Any]) -> dict[str, Any]:
        configured = self._validate(value["values"])
        fields = []
        for name, (group, kind, choices) in EDITABLE_SETTINGS.items():
            current = getattr(self.current, name)
            desired = getattr(configured, name)
            item = {
                "name": name,
                "env": f"EVERGARDEN_{name.upper()}",
                "group": group,
                "type": kind,
                "choices": choices,
                "value": desired,
                "effective": current,
                "overridden": name in value["values"],
                "pending": current != desired,
                "risk": name in RISK_SETTINGS,
            }
            for constraint in type(self.current).model_fields[name].metadata:
                for attribute, key in (("ge", "min"), ("le", "max")):
                    bound = getattr(constraint, attribute, None)
                    if bound is not None:
                        item[key] = bound
            fields.append(item)
        return {
            "revision": revision(value),
            "fields": fields,
            "restart_required": any(f["pending"] for f in fields),
        }

    def snapshot(self) -> dict[str, Any]:
        with self.store.lock():
            return self._public(self._read())

    def update(
        self, changes: dict[str, Any], *, expected_revision: str, acknowledge_risk: bool = False
    ) -> dict[str, Any]:
        with self.store.lock():
            value = self._read()
            if expected_revision != revision(value):
                raise RuntimeSettingsConflict("settings changed; reload before editing")
            previous = self._validate(value["values"])
            if acknowledge_risk is not True and any(
                key in RISK_SETTINGS and val != getattr(previous, key)
                for key, val in changes.items()
            ):
                raise RuntimeSettingsError(
                    "permission changes require explicit risk acknowledgement"
                )
            updated = {**value["values"], **changes}
            self._validate(updated)
            stored = {"schema_version": 1, "values": updated}
            if len(canonical(stored)) > 30 * 1024:
                raise RuntimeSettingsError("runtime settings exceed the size limit")
            self.store.write_json(stored)
            return self._public(stored)
