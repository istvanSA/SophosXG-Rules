"""Read and update the supported rule settings for the dashboard editor."""

from asyncio import gather
from hashlib import sha256
import json
from typing import Any

from .api import POLICY_ROUTES, Rule, SophosApiError, SophosClient

FIELD_PATHS = {
    "application_policy": ("securityFeatures", "applicationPolicy"),
    "web_policy": ("securityFeatures", "webPolicy"),
    "traffic_shaping_policy": ("qos", "trafficShapingPolicy"),
    "block_quic": ("securityFeatures", "blockQuicProtocol"),
}


def _section(details: dict[str, Any], key: str) -> dict[str, Any]:
    value = details.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SophosApiError("Unexpected firewall rule settings")
    return value


def rule_snapshot(details: dict[str, Any], family: str) -> dict[str, Any]:
    """Expose the rule editor fields and a revision of the confirmed state."""
    security = _section(details, "securityFeatures")
    values = {
        "enabled": details["enabled"],
        "block_quic": security.get("blockQuicProtocol", False),
    }
    if not isinstance(values["block_quic"], bool):
        raise SophosApiError("Unexpected Block QUIC state")
    for field in POLICY_ROUTES:
        section, key = FIELD_PATHS[field]
        policy = _section(details, section).get(key)
        name = policy.get("name") if isinstance(policy, dict) else None
        if policy is not None and (not isinstance(name, str) or not name):
            raise SophosApiError("Unexpected policy reference on the firewall rule")
        values[field] = name
    revision = sha256(json.dumps(details, sort_keys=True).encode()).hexdigest()
    return {
        "name": details["name"],
        "family": family,
        "action": details.get("action"),
        "policy_editable": (
            details.get("ruleType") == "firewall" and details.get("action") == "accept"
        ),
        "scans_web": security.get("scanHttpAndDecryptedHttps") is True,
        "revision": revision,
        "values": values,
    }


async def async_policy_options(client: SophosClient) -> dict[str, list[str] | None]:
    """Load dropdowns independently so a denied catalog does not block the others."""
    kinds = list(POLICY_ROUTES)
    results = await gather(
        *(client.async_list_policy_names(kind) for kind in kinds),
        return_exceptions=True,
    )
    options = {}
    for kind, result in zip(kinds, results, strict=True):
        if isinstance(result, SophosApiError):
            options[kind] = None
        elif isinstance(result, BaseException):
            raise result
        else:
            options[kind] = result
    return options


async def async_apply_changes(
    client: SophosClient,
    rule: Rule,
    revision: str,
    changes: dict[str, Any],
) -> dict[str, Any]:
    """Validate a draft, send a narrow patch, and verify the result."""
    details = await client.async_get_rule_details(rule)
    current = rule_snapshot(details, rule.family)
    if current["revision"] != revision:
        raise SophosApiError("The rule changed in Sophos. Refresh the rule before editing it.")

    values = current["values"]
    changes = {key: value for key, value in changes.items() if value != values[key]}
    if not changes:
        return current
    if changes.keys() & FIELD_PATHS.keys() and not current["policy_editable"]:
        raise SophosApiError("Policy settings can be edited on standard allow rules")

    desired = {**values, **changes}
    security = _section(details, "securityFeatures")
    if {"web_policy", "block_quic"} & changes.keys() and (
        not desired["web_policy"] and not current["scans_web"]
    ):
        if desired["block_quic"]:
            raise SophosApiError("Block QUIC requires a web policy or HTTP scanning")
        if "web_policy" in changes and any(
            security.get(key)
            for key in ("webProxy", "webCategoryBasedQosPolicy", "decryptHTTPSWebProxyMode")
        ):
            raise SophosApiError(
                "Clear the dependent web settings in Sophos before removing this policy"
            )
    if (
        "application_policy" in changes
        and desired["application_policy"] is None
        and security.get("applicationBasedQosPolicy")
    ):
        raise SophosApiError(
            "Turn off application-based traffic shaping in Sophos before removing this policy"
        )

    requested_policies = {
        kind: changes[kind]
        for kind in POLICY_ROUTES
        if kind in changes and changes[kind] is not None
    }
    catalogs = await gather(*(client.async_list_policy_names(kind) for kind in requested_policies))
    if any(
        name not in catalog
        for name, catalog in zip(requested_policies.values(), catalogs, strict=True)
    ):
        raise SophosApiError("A selected policy is no longer available. Refresh the rule.")

    patch: dict[str, Any] = {}
    for field, value in changes.items():
        if field == "enabled":
            patch[field] = value
            continue
        section, key = FIELD_PATHS[field]
        if field in POLICY_ROUTES and value is not None:
            value = {"name": value}
        patch.setdefault(section, {})[key] = value

    actual = rule_snapshot(await client.async_patch_rule(rule, patch), rule.family)
    if any(actual["values"][key] != value for key, value in changes.items()):
        raise SophosApiError(
            "The firewall did not confirm every change. Refresh to see its current settings."
        )
    return actual
