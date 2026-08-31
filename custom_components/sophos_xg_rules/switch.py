"""Switch platform for Sophos XG Firewall Rule Control."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SophosXGRulesData
from .api import SophosApiError
from .const import CONF_RULES, DOMAIN
from .coordinator import SophosRulesCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one switch entity per configured firewall rule."""
    data: SophosXGRulesData = hass.data[DOMAIN][entry.entry_id]
    rule_names: list[str] = list(entry.options.get(CONF_RULES, []))

    async_add_entities(
        SophosFirewallRuleSwitch(data.coordinator, entry, rule_name)
        for rule_name in rule_names
    )


class SophosFirewallRuleSwitch(CoordinatorEntity[SophosRulesCoordinator], SwitchEntity):
    """Represents a single Sophos firewall rule as an on/off switch."""

    _attr_device_class = SwitchDeviceClass.SWITCH
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: SophosRulesCoordinator,
        entry: ConfigEntry,
        rule_name: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._rule_name = rule_name
        self._attr_unique_id = f"{entry.entry_id}_{rule_name}"
        self._attr_name = rule_name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"Sophos Firewall ({entry.data.get('host')})",
            manufacturer="Sophos",
            model="Firewall rule control",
        )

    @property
    def is_on(self) -> bool | None:
        state = self.coordinator.data.get(self._rule_name)
        return state.enabled if state else None

    @property
    def available(self) -> bool:
        return super().available and self._rule_name in self.coordinator.data

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._async_set_status(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._async_set_status(False)

    async def _async_set_status(self, enabled: bool) -> None:
        data: SophosXGRulesData = self.hass.data[DOMAIN][self._entry.entry_id]
        try:
            await data.client.async_set_rule_status(self._rule_name, enabled)
        except SophosApiError as err:
            _LOGGER.error(
                "Failed to %s rule '%s': %s",
                "enable" if enabled else "disable",
                self._rule_name,
                err,
            )
            raise
        await self.coordinator.async_request_refresh()
