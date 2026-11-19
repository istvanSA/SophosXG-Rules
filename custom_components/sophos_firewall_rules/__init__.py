"""Expose selected Sophos Firewall rules as Home Assistant switches."""

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_API_KEY, CONF_HOST, CONF_PORT, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from yarl import URL

from .api import SophosClient
from .coordinator import RulesCoordinator

PLATFORMS = [Platform.SWITCH]
type SophosConfigEntry = ConfigEntry[RulesCoordinator]


def make_client(hass: HomeAssistant, data: dict[str, Any]) -> SophosClient:
    """Use the Home Assistant HTTP session for this entry's TLS setting."""
    origin = URL.build(scheme="https", host=data[CONF_HOST], port=data[CONF_PORT])
    session = async_get_clientsession(hass, verify_ssl=data[CONF_VERIFY_SSL])
    return SophosClient(session, origin, data[CONF_API_KEY])


async def async_setup_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Validate access and set up the switch platform."""
    coordinator = RulesCoordinator(hass, entry, make_client(hass, entry.data))
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Unload the switch platform."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
