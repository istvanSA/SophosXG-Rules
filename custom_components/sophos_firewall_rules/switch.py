"""Switch entities for selected Sophos Firewall rules."""

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SophosConfigEntry
from .const import CONF_RULES, DOMAIN
from .coordinator import RulesCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create switches for the rules chosen in the integration settings."""
    async_add_entities(
        RuleSwitch(entry, key, name)
        for key, name in entry.options.get(CONF_RULES, {}).items()
    )


class RuleSwitch(CoordinatorEntity[RulesCoordinator], SwitchEntity):
    """Toggle a rule's enabled state on the firewall."""

    _attr_has_entity_name = True

    def __init__(self, entry: SophosConfigEntry, key: str, name: str) -> None:
        super().__init__(entry.runtime_data)
        self._key = key
        self._fallback_name = name
        self._attr_unique_id = f"{entry.entry_id}:{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
            manufacturer="Sophos",
        )

    @property
    def name(self) -> str:
        """Use the latest name reported by Sophos."""
        rule = self.coordinator.data.get(self._key)
        return rule.name if rule else self._fallback_name

    @property
    def available(self) -> bool:
        """Report availability only when the rule is present in a current snapshot."""
        return super().available and self._key in self.coordinator.data

    @property
    def is_on(self) -> bool | None:
        """Read the rule's enabled state from the firewall snapshot."""
        rule = self.coordinator.data.get(self._key)
        return rule.enabled if rule else None

    async def async_turn_on(self, **kwargs) -> None:
        """Enable the firewall rule."""
        await self.coordinator.async_set_enabled(self._key, True)

    async def async_turn_off(self, **kwargs) -> None:
        """Disable the firewall rule."""
        await self.coordinator.async_set_enabled(self._key, False)
