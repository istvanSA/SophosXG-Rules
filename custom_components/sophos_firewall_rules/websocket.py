"""Administrator-only commands for the firewall rule card."""

from typing import Any

from homeassistant.components import websocket_api
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, callback
import voluptuous as vol

from .api import POLICY_ROUTES, Rule, SophosApiError
from .const import CONF_RULES, DOMAIN
from .coordinator import RulesCoordinator
from .editor import async_policy_options, rule_snapshot

_RULE_FIELDS = {vol.Required("entry_id"): str, vol.Required("rule_key"): str}
_POLICY_VALUE = vol.Any(None, vol.All(str, vol.Length(min=1, max=60)))
_CHANGES = vol.Schema(
    {
        vol.Optional("enabled"): bool,
        vol.Optional("block_quic"): bool,
        **{vol.Optional(kind): _POLICY_VALUE for kind in POLICY_ROUTES},
    }
)


@callback
def async_register_commands(hass: HomeAssistant) -> None:
    """Register the card commands once at integration setup."""
    websocket_api.async_register_command(hass, async_list_rules)
    websocket_api.async_register_command(hass, async_read_rule)
    websocket_api.async_register_command(hass, async_edit_rule)


def _selected_rule(
    hass: HomeAssistant, msg: dict[str, Any]
) -> tuple[RulesCoordinator, Rule]:
    entry = hass.config_entries.async_get_entry(msg["entry_id"])
    if (
        entry is not None
        and entry.domain == DOMAIN
        and entry.state is ConfigEntryState.LOADED
        and msg["rule_key"] in entry.options.get(CONF_RULES, {})
    ):
        coordinator = entry.runtime_data
        if rule := coordinator.data.get(msg["rule_key"]):
            return coordinator, rule
    raise SophosApiError("This rule is unavailable or no longer selected in the integration")


@websocket_api.websocket_command({vol.Required("type"): f"{DOMAIN}/rules"})
@websocket_api.require_admin
@callback
def async_list_rules(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """List the rules exposed by loaded config entries."""
    rules = []
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.state is not ConfigEntryState.LOADED:
            continue
        for key in entry.options.get(CONF_RULES, {}):
            if rule := entry.runtime_data.data.get(key):
                rules.append(
                    {
                        "entry_id": entry.entry_id,
                        "rule_key": key,
                        "name": rule.name,
                        "family": rule.family,
                        "firewall": entry.title,
                    }
                )
    connection.send_result(msg["id"], rules)


@websocket_api.websocket_command(
    {vol.Required("type"): f"{DOMAIN}/read_rule", **_RULE_FIELDS}
)
@websocket_api.require_admin
@websocket_api.async_response
async def async_read_rule(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Read the current rule and its available policy choices."""
    try:
        coordinator, rule = _selected_rule(hass, msg)
        details = await coordinator.client.async_get_rule_details(rule)
        snapshot = rule_snapshot(details, rule.family)
        snapshot["options"] = (
            await async_policy_options(coordinator.client)
            if snapshot["policy_editable"]
            else {}
        )
    except SophosApiError as err:
        connection.send_error(msg["id"], "sophos_rule_error", str(err))
        return
    connection.send_result(msg["id"], snapshot)


@websocket_api.websocket_command(
    {
        vol.Required("type"): f"{DOMAIN}/edit_rule",
        **_RULE_FIELDS,
        vol.Required("revision"): vol.Match(r"^[0-9a-f]{64}$"),
        vol.Required("changes"): _CHANGES,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def async_edit_rule(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]
) -> None:
    """Apply and verify changes to an exposed rule."""
    try:
        coordinator, rule = _selected_rule(hass, msg)
        snapshot = await coordinator.async_edit_rule(rule, msg["revision"], msg["changes"])
    except SophosApiError as err:
        connection.send_error(msg["id"], "sophos_rule_error", str(err))
        return
    connection.send_result(msg["id"], snapshot)
