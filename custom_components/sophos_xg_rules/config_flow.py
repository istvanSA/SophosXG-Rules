"""Config and options flow for Sophos XG Firewall Rule Control."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import SophosApiError, SophosAuthError, SophosConnectionError, SophosXGClient
from .const import (
    CONF_RULES,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
    }
)


async def _validate_connection(hass, data: dict[str, Any]) -> None:
    """Raise SophosApiError subclasses on failure, else return."""
    session = async_get_clientsession(hass, verify_ssl=data[CONF_VERIFY_SSL])
    client = SophosXGClient(
        session=session,
        host=data[CONF_HOST],
        port=data[CONF_PORT],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        verify_ssl=data[CONF_VERIFY_SSL],
    )
    await client.async_test_connection()


class SophosXGRulesConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle initial setup: host, username, password."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(
                f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}"
            )
            self._abort_if_unique_id_configured()

            try:
                await _validate_connection(self.hass, user_input)
            except SophosAuthError:
                errors["base"] = "invalid_auth"
            except SophosConnectionError:
                errors["base"] = "cannot_connect"
            except SophosApiError:
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=user_input[CONF_HOST],
                    data=user_input,
                    options={CONF_RULES: []},
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> SophosXGRulesOptionsFlow:
        return SophosXGRulesOptionsFlow(config_entry)


class SophosXGRulesOptionsFlow(config_entries.OptionsFlow):
    """Manage the list of tracked firewall rule names after setup."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry

    @property
    def _rules(self) -> list[str]:
        return list(self._entry.options.get(CONF_RULES, []))

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        return self.async_show_menu(
            step_id="init",
            menu_options=["add_rule", "remove_rule"],
        )

    async def async_step_add_rule(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            rule_name = user_input["rule_name"].strip()
            rules = self._rules

            if not rule_name:
                errors["rule_name"] = "invalid_rule_name"
            elif rule_name in rules:
                errors["rule_name"] = "rule_already_added"
            else:
                session = async_get_clientsession(
                    self.hass, verify_ssl=self._entry.data.get(CONF_VERIFY_SSL, False)
                )
                client = SophosXGClient(
                    session=session,
                    host=self._entry.data[CONF_HOST],
                    port=self._entry.data[CONF_PORT],
                    username=self._entry.data[CONF_USERNAME],
                    password=self._entry.data[CONF_PASSWORD],
                    verify_ssl=self._entry.data.get(CONF_VERIFY_SSL, False),
                )
                try:
                    await client.async_get_rule_state(rule_name)
                except SophosApiError:
                    errors["rule_name"] = "rule_not_found"
                else:
                    rules.append(rule_name)
                    return self.async_create_entry(data={CONF_RULES: rules})

        return self.async_show_form(
            step_id="add_rule",
            data_schema=vol.Schema({vol.Required("rule_name"): str}),
            errors=errors,
        )

    async def async_step_remove_rule(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        rules = self._rules

        if not rules:
            return self.async_abort(reason="no_rules_configured")

        if user_input is not None:
            remaining = [r for r in rules if r not in user_input["rule_names"]]
            return self.async_create_entry(data={CONF_RULES: remaining})

        return self.async_show_form(
            step_id="remove_rule",
            data_schema=vol.Schema(
                {
                    vol.Required("rule_names"): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=rules,
                            multiple=True,
                            mode=selector.SelectSelectorMode.LIST,
                        )
                    )
                }
            ),
        )
