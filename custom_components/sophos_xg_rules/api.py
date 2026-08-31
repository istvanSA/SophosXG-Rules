"""Minimal async client for the Sophos XG / Sophos Firewall XML API.

The Sophos firewall API is not REST/JSON - it is a single endpoint
(``/webconsole/APIController``) that accepts an XML payload describing a
``Login`` block plus a ``Get``/``Set``/``Remove`` operation.

There is no way to patch a single field on a FirewallRule. To flip a rule's
Status we therefore always:

    1. ``Get`` the rule's full current XML by Name.
    2. Change only the ``<Status>`` element's text.
    3. ``Set operation="update"`` with that same XML back to the firewall.

This avoids needing to know/hardcode every possible field for every rule
type (Network / User / HTTPBased / WAF, etc.).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from xml.etree import ElementTree as ET

import aiohttp

from .const import API_TIMEOUT

_LOGGER = logging.getLogger(__name__)


class SophosApiError(Exception):
    """Base error for the Sophos API client."""


class SophosAuthError(SophosApiError):
    """Raised when login fails (bad username/password)."""


class SophosConnectionError(SophosApiError):
    """Raised when the firewall cannot be reached."""


class SophosRuleNotFoundError(SophosApiError):
    """Raised when a named firewall rule does not exist."""


@dataclass
class RuleState:
    """Represents the current known state of a firewall rule."""

    name: str
    enabled: bool


class SophosXGClient:
    """Talks to the Sophos XG / Sophos Firewall XML API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_ssl: bool = False,
    ) -> None:
        self._session = session
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl

    @property
    def _url(self) -> str:
        return f"https://{self._host}:{self._port}/webconsole/APIController"

    def _login_element(self) -> ET.Element:
        login = ET.Element("Login")
        ET.SubElement(login, "Username").text = self._username
        password = ET.SubElement(login, "Password")
        password.set("passwordform", "plain")
        password.text = self._password
        return login

    async def _post(self, request_root: ET.Element) -> ET.Element:
        """POST an XML <Request> element and return the parsed <Response>."""
        xml_bytes = b'<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(
            request_root, encoding="unicode"
        ).encode("utf-8")

        try:
            async with self._session.post(
                self._url,
                data={"reqxml": xml_bytes},
                ssl=self._verify_ssl,
                timeout=aiohttp.ClientTimeout(total=API_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    raise SophosConnectionError(
                        f"Unexpected HTTP status {resp.status} from firewall"
                    )
                text = await resp.text()
        except aiohttp.ClientError as err:
            raise SophosConnectionError(str(err)) from err
        except TimeoutError as err:
            raise SophosConnectionError("Timed out contacting firewall") from err

        try:
            response_root = ET.fromstring(text)
        except ET.ParseError as err:
            raise SophosApiError(f"Could not parse firewall response: {err}") from err

        login_status = response_root.findtext("Login/status", default="")
        if login_status and "Authentication Successful" not in login_status:
            raise SophosAuthError(login_status)

        return response_root

    async def async_test_connection(self) -> None:
        """Verify host/credentials are valid by attempting a lightweight Get.

        Raises SophosAuthError / SophosConnectionError / SophosApiError on
        failure. Returns normally on success.
        """
        request = ET.Element("Request")
        request.append(self._login_element())
        get = ET.SubElement(request, "Get")
        firewall_rule = ET.SubElement(get, "FirewallRule")
        filt = ET.SubElement(firewall_rule, "Filter")
        key = ET.SubElement(filt, "key")
        key.set("name", "Name")
        key.set("criteria", "=")
        # An intentionally-empty criteria value: we only care that the
        # firewall accepts the login and answers the FirewallRule Get,
        # not that any particular rule exists.
        key.text = "__ha_sophos_xg_rules_connection_test__"

        await self._post(request)

    async def async_get_rule_element(self, rule_name: str) -> ET.Element:
        """Fetch the full <FirewallRule> XML element for a rule by name."""
        request = ET.Element("Request")
        request.append(self._login_element())
        get = ET.SubElement(request, "Get")
        firewall_rule = ET.SubElement(get, "FirewallRule")
        filt = ET.SubElement(firewall_rule, "Filter")
        key = ET.SubElement(filt, "key")
        key.set("name", "Name")
        key.set("criteria", "=")
        key.text = rule_name

        response_root = await self._post(request)

        rule_element = self._find_rule_by_name(response_root, rule_name)
        if rule_element is not None:
            return rule_element

        # Some firmware versions don't honour the Filter for FirewallRule -
        # fall back to an unfiltered Get and search client-side.
        request = ET.Element("Request")
        request.append(self._login_element())
        get = ET.SubElement(request, "Get")
        ET.SubElement(get, "FirewallRule")
        response_root = await self._post(request)

        rule_element = self._find_rule_by_name(response_root, rule_name)
        if rule_element is None:
            raise SophosRuleNotFoundError(rule_name)
        return rule_element

    @staticmethod
    def _find_rule_by_name(response_root: ET.Element, rule_name: str) -> ET.Element | None:
        for rule_element in response_root.findall("FirewallRule"):
            if rule_element.findtext("Name") == rule_name:
                return rule_element
        return None

    @staticmethod
    def _status_from_element(rule_element: ET.Element) -> bool:
        status_text = (rule_element.findtext("Status") or "").strip().lower()
        return status_text == "enable"

    async def async_get_rule_state(self, rule_name: str) -> RuleState:
        """Return the current enabled/disabled state of a rule."""
        rule_element = await self.async_get_rule_element(rule_name)
        return RuleState(name=rule_name, enabled=self._status_from_element(rule_element))

    async def async_set_rule_status(self, rule_name: str, enabled: bool) -> None:
        """Enable or disable a firewall rule by name."""
        rule_element = await self.async_get_rule_element(rule_name)

        status_element = rule_element.find("Status")
        if status_element is None:
            status_element = ET.SubElement(rule_element, "Status")
        status_element.text = "Enable" if enabled else "Disable"

        # transactionid is only meaningful as an echo field on Set - clear it.
        rule_element.set("transactionid", "")

        request = ET.Element("Request")
        request.append(self._login_element())
        set_el = ET.SubElement(request, "Set")
        set_el.set("operation", "update")
        set_el.append(rule_element)

        response_root = await self._post(request)

        result = response_root.find("FirewallRule")
        status_node = result.find("Status") if result is not None else None
        code = status_node.get("code") if status_node is not None else None
        message = (status_node.text or "").strip() if status_node is not None else ""

        if code not in (None, "200"):
            raise SophosApiError(
                f"Firewall rejected update for rule '{rule_name}' "
                f"(code {code}): {message or 'unknown error'}"
            )
