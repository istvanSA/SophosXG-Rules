"""Poll the firewall and serialize rule updates with reads."""

from asyncio import Lock
from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import Rule, SophosApiError, SophosAuthError, SophosClient
from .const import DOMAIN
from .editor import async_apply_changes

_LOGGER = logging.getLogger(__name__)


class RulesCoordinator(DataUpdateCoordinator[dict[str, Rule]]):
    """Share one firewall rule snapshot among all configured switches."""

    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, client: SophosClient
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(seconds=60),
            always_update=False,
        )
        self.client = client
        self._lock = Lock()

    async def _async_update_data(self) -> dict[str, Rule]:
        async with self._lock:
            try:
                return await self.client.async_list_rules()
            except SophosAuthError as err:
                raise ConfigEntryAuthFailed(str(err)) from err
            except SophosApiError as err:
                raise UpdateFailed(str(err)) from err

    async def async_set_enabled(self, key: str, enabled: bool) -> None:
        """Update a selected rule and refresh state after the attempt."""
        try:
            async with self._lock:
                rule = self.data.get(key)
                if rule is None or not self.last_update_success:
                    raise HomeAssistantError("The firewall rule is currently unavailable")
                await self.client.async_set_enabled(rule, enabled)
        except SophosApiError as err:
            await self.async_refresh()
            raise HomeAssistantError(str(err)) from err
        await self.async_refresh()

    async def async_edit_rule(
        self, rule: Rule, revision: str, changes: dict[str, Any]
    ) -> dict[str, Any]:
        """Serialize editor writes with rule polling and existing switches."""
        try:
            async with self._lock:
                return await async_apply_changes(self.client, rule, revision, changes)
        finally:
            await self.async_refresh()
