"""Coordinator that polls the Sophos firewall for tracked rule states."""

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import RuleState, SophosApiError, SophosXGClient
from .const import DOMAIN, UPDATE_INTERVAL_SECONDS

_LOGGER = logging.getLogger(__name__)


class SophosRulesCoordinator(DataUpdateCoordinator[dict[str, RuleState]]):
    """Polls the configured list of firewall rules for their current status."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: SophosXGClient,
        rule_names: list[str],
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS),
        )
        self.client = client
        self.rule_names = rule_names

    async def _async_update_data(self) -> dict[str, RuleState]:
        results: dict[str, RuleState] = {}
        for name in self.rule_names:
            try:
                results[name] = await self.client.async_get_rule_state(name)
            except SophosApiError as err:
                raise UpdateFailed(f"Error fetching rule '{name}': {err}") from err
        return results
