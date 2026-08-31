"""The Sophos XG Firewall Rule Control integration."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import SophosXGClient
from .const import CONF_RULES, CONF_VERIFY_SSL, DOMAIN
from .coordinator import SophosRulesCoordinator

PLATFORMS: list[Platform] = [Platform.SWITCH]


@dataclass
class SophosXGRulesData:
    """Runtime data stored per config entry."""

    client: SophosXGClient
    coordinator: SophosRulesCoordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Sophos XG Firewall Rule Control from a config entry."""
    verify_ssl = entry.data.get(CONF_VERIFY_SSL, False)
    session = async_get_clientsession(hass, verify_ssl=verify_ssl)

    client = SophosXGClient(
        session=session,
        host=entry.data[CONF_HOST],
        port=entry.data[CONF_PORT],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        verify_ssl=verify_ssl,
    )

    rule_names: list[str] = list(entry.options.get(CONF_RULES, []))
    coordinator = SophosRulesCoordinator(hass, client, rule_names)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = SophosXGRulesData(
        client=client, coordinator=coordinator
    )

    entry.async_on_unload(entry.add_update_listener(async_update_listener))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok


async def async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the entry when options (the tracked rule list) change."""
    await hass.config_entries.async_reload(entry.entry_id)
