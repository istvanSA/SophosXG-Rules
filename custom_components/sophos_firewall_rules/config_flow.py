"""Set up API credentials and select which firewall rules to expose."""

from collections.abc import Mapping
from ipaddress import IPv6Address
import logging
from typing import Any

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_API_KEY, CONF_HOST, CONF_PORT, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import selector
import voluptuous as vol
from yarl import URL

from . import make_client
from .api import (
    Rule,
    SophosApiError,
    SophosAuthError,
    SophosConnectionError,
    SophosPermissionError,
    SophosUnsupportedError,
)
from .const import CONF_RULES, DEFAULT_PORT, DOMAIN

_LOGGER = logging.getLogger(__name__)
_KEY_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
)
_CONNECTION_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): vol.All(
            vol.Coerce(int), vol.Range(min=1, max=65535)
        ),
        vol.Required(CONF_API_KEY): _KEY_SELECTOR,
        vol.Required(CONF_VERIFY_SSL, default=True): bool,
    }
)


def _host(value: str) -> str:
    host = value.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or any(char.isspace() or char in "/?#@\\%" for char in host):
        raise ValueError("Invalid firewall host")
    if ":" in host:
        return IPv6Address(host).compressed
    if host.startswith((".", "-")) or any(char in "[]" for char in host):
        raise ValueError("Invalid firewall host")
    origin = URL.build(scheme="https", host=host)
    if origin.raw_host is None:
        raise ValueError("Invalid firewall host")
    return origin.raw_host


async def _discover(
    hass: HomeAssistant, data: dict[str, Any]
) -> tuple[dict[str, Rule], str | None]:
    try:
        return await make_client(hass, data).async_list_rules(), None
    except SophosAuthError:
        return {}, "invalid_auth"
    except SophosPermissionError:
        return {}, "permission_denied"
    except SophosUnsupportedError:
        return {}, "unsupported_firmware"
    except SophosConnectionError:
        return {}, "cannot_connect"
    except SophosApiError as err:
        _LOGGER.warning("Could not discover Sophos firewall rules: %s", err)
        return {}, "unexpected_response"


def _selection_schema(
    rules: dict[str, Rule], selected: Mapping[str, str]
) -> vol.Schema:
    labels = {
        key: f"{rule.name} (IPv{rule.family[-1]})"
        for key, rule in rules.items()
    }
    for key, name in selected.items():
        labels.setdefault(key, f"{name} ({key.split(':', 1)[0]} · unavailable)")
    options = [
        selector.SelectOptionDict(value=key, label=label)
        for key, label in sorted(labels.items(), key=lambda item: item[1].casefold())
    ]
    return vol.Schema(
        {
            vol.Required(CONF_RULES, default=list(selected)): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=options,
                    multiple=True,
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            )
        }
    )


def _selection(
    keys: list[str], rules: dict[str, Rule], existing: Mapping[str, str]
) -> dict[str, str]:
    return {
        key: rules[key].name if key in rules else existing[key]
        for key in keys
        if key in rules or key in existing
    }


class SophosRulesConfigFlow(ConfigFlow, domain=DOMAIN):
    """Connect Home Assistant to the Sophos REST API."""

    VERSION = 1

    def __init__(self) -> None:
        self._connection: dict[str, Any] = {}
        self._rules: dict[str, Rule] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Validate the firewall URL and API key."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                host = _host(user_input[CONF_HOST])
            except (UnicodeError, ValueError):
                errors[CONF_HOST] = "invalid_host"
            else:
                port = user_input[CONF_PORT]
                api_key = user_input[CONF_API_KEY].strip()
                if not api_key or any(char.isspace() for char in api_key):
                    errors[CONF_API_KEY] = "invalid_auth"
                else:
                    self._connection = {
                        **user_input,
                        CONF_HOST: host,
                        CONF_API_KEY: api_key,
                    }
                    self._rules, error = await _discover(self.hass, self._connection)
                    if error is None:
                        origin = URL.build(scheme="https", host=host, port=port)
                        await self.async_set_unique_id(str(origin))
                        self._abort_if_unique_id_configured()
                        return await self.async_step_rules()
                    errors["base"] = error

        suggested = {
            key: value for key, value in (user_input or {}).items() if key != CONF_API_KEY
        }
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(_CONNECTION_SCHEMA, suggested),
            errors=errors,
        )

    async def async_step_rules(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Create switches for the explicitly selected rules."""
        if user_input is not None:
            return self.async_create_entry(
                title=f"Sophos Firewall ({self._connection[CONF_HOST]})",
                data=self._connection,
                options={CONF_RULES: _selection(user_input[CONF_RULES], self._rules, {})},
            )
        return self.async_show_form(
            step_id="rules", data_schema=_selection_schema(self._rules, {})
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Start API key replacement for an existing firewall."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Validate and save a replacement key."""
        errors: dict[str, str] = {}
        if user_input is not None:
            api_key = user_input[CONF_API_KEY].strip()
            if not api_key or any(char.isspace() for char in api_key):
                errors[CONF_API_KEY] = "invalid_auth"
            else:
                entry = self._get_reauth_entry()
                _, error = await _discover(
                    self.hass, {**entry.data, CONF_API_KEY: api_key}
                )
                if error is None:
                    return self.async_update_reload_and_abort(
                        entry, data_updates={CONF_API_KEY: api_key}
                    )
                errors["base"] = error
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_API_KEY): _KEY_SELECTOR}),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> "SophosRulesOptionsFlow":
        """Manage the selected rules."""
        return SophosRulesOptionsFlow()


class SophosRulesOptionsFlow(OptionsFlowWithReload):
    """Discover rules afresh when the user opens Configure."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Select the rules that should have switch entities."""
        selected = self.config_entry.options.get(CONF_RULES, {})
        if user_input is not None:
            return self.async_create_entry(
                data={CONF_RULES: _selection(user_input[CONF_RULES], self._rules, selected)}
            )
        self._rules, error = await _discover(self.hass, dict(self.config_entry.data))
        if error is not None:
            return self.async_abort(reason=error)
        return self.async_show_form(
            step_id="init", data_schema=_selection_schema(self._rules, selected)
        )
