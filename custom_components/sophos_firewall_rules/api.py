"""Client for the Sophos Firewall configuration REST API."""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

import aiohttp
from yarl import URL

FAMILIES = ("ipv4", "ipv6")


class SophosApiError(Exception):
    """A firewall request failed or could not be confirmed."""


class SophosAuthError(SophosApiError):
    """The firewall rejected the API key."""


class SophosPermissionError(SophosApiError):
    """The API key or source address lacks access."""


class SophosConnectionError(SophosApiError):
    """The firewall could not be reached."""


class SophosUnsupportedError(SophosApiError):
    """The firewall configuration API was not found."""


@dataclass(frozen=True)
class Rule:
    """A firewall rule's identity and enabled state."""

    family: str
    id: str
    name: str
    enabled: bool

    @property
    def key(self) -> str:
        """Return the stable key for selection and entity registration."""
        return f"{self.family}:{self.id}"

    @classmethod
    def from_json(cls, family: str, data: Any) -> "Rule":
        """Decode the fields the integration needs."""
        if not isinstance(data, dict):
            raise SophosApiError("expected a rule object")
        try:
            rule_id = str(UUID(data["id"]))
        except (AttributeError, KeyError, TypeError, ValueError):
            raise SophosApiError("expected a rule UUID in id") from None
        name = data.get("name")
        enabled = data.get("enabled")
        if not isinstance(name, str) or not name:
            raise SophosApiError("expected a nonempty rule name")
        if not isinstance(enabled, bool):
            raise SophosApiError("expected a boolean enabled field")
        return cls(family, rule_id, name, enabled)


class SophosClient:
    """Read and update rules using a bearer API key."""

    def __init__(
        self, session: aiohttp.ClientSession, origin: URL, api_key: str
    ) -> None:
        self._session = session
        self._base = origin / "api/firewall-config/v1/firewall/rules"
        self._headers = {"Accept": "application/json", "Authorization": f"Bearer {api_key}"}

    async def _request(
        self,
        method: str,
        url: URL,
        *,
        params: dict[str, str] | None = None,
        payload: dict[str, bool] | None = None,
        collection: bool = False,
    ) -> Any:
        try:
            async with self._session.request(
                method,
                url,
                headers=self._headers,
                params=params,
                json=payload,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response:
                if response.status == 401:
                    raise SophosAuthError("The firewall rejected the API key")
                if response.status == 403:
                    raise SophosPermissionError("The firewall denied API access")
                if collection and response.status == 404:
                    raise SophosUnsupportedError(
                        "Firewall configuration API endpoint not found"
                    )
                if response.status != 200:
                    raise SophosApiError(f"{method} returned HTTP {response.status}")
                try:
                    return await response.json()
                except aiohttp.ContentTypeError:
                    raise SophosApiError(
                        f"{method} returned HTTP 200 without a JSON content type"
                    ) from None
                except ValueError:
                    raise SophosApiError(
                        f"{method} returned HTTP 200 with invalid JSON"
                    ) from None
        except (TimeoutError, aiohttp.ClientError):
            raise SophosConnectionError(
                "Could not complete request to the firewall"
            ) from None

    async def async_list_rules(self) -> dict[str, Rule]:
        """Read every page of IPv4 and IPv6 rules."""
        rules: dict[str, Rule] = {}
        for family in FAMILIES:
            page = 1
            while True:
                try:
                    page_rules, has_next = await self._async_read_rule_page(family, page)
                except (
                    SophosAuthError,
                    SophosPermissionError,
                    SophosUnsupportedError,
                    SophosConnectionError,
                ):
                    raise
                except SophosApiError as err:
                    raise SophosApiError(
                        f"{family} rule list, page {page}: {err}"
                    ) from None
                if rules.keys() & page_rules.keys():
                    raise SophosApiError(f"{family} rule list repeated a rule on page {page}")
                rules.update(page_rules)
                if not has_next:
                    break
                page += 1
        return rules

    async def _async_read_rule_page(
        self, family: str, page: int
    ) -> tuple[dict[str, Rule], bool]:
        data = await self._request(
            "GET",
            self._base / family,
            params={"page": str(page), "pageTotal": "true"},
            collection=True,
        )
        if not isinstance(data, dict) or not isinstance(data.get("items"), list):
            raise SophosApiError("expected an items array")
        if not isinstance(pages := data.get("pages"), dict):
            raise SophosApiError("expected a pages object")

        items = data["items"]
        current = pages.get("current")
        if type(current) is not int or current != page:
            raise SophosApiError("unexpected current page number")

        total = pages.get("total")
        if total is None:
            size = pages.get("size")
            if type(size) is not int or size < len(items) or size < 0:
                raise SophosApiError("invalid page size without a page total")
            has_next = size > 0 and len(items) == size
        elif type(total) is int and total >= 0:
            has_next = page < total
        else:
            raise SophosApiError("invalid page total")

        rules: dict[str, Rule] = {}
        for item in items:
            rule = Rule.from_json(family, item)
            rules[rule.key] = rule
        return rules, has_next

    async def async_set_enabled(self, rule: Rule, enabled: bool) -> None:
        """Patch the enabled field and verify it with a fresh GET."""
        url = self._base / rule.family / rule.id
        try:
            await self._request("PATCH", url, payload={"enabled": enabled})
        except SophosConnectionError:
            # Sophos may have applied the change even if the client timed out.
            # Read it back before deciding whether the action succeeded.
            pass
        actual = Rule.from_json(rule.family, await self._request("GET", url))
        if actual.id != rule.id or actual.enabled is not enabled:
            raise SophosApiError("The firewall did not confirm the requested rule state")
