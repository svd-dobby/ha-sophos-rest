"""Small async client for the Sophos Firewall REST API (SFOS v23+)."""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote

import aiohttp

from .const import API_BASE, PATH_DHCP_LEASES_V4, PATH_DHCP_SERVERS_V4

TIMEOUT = aiohttp.ClientTimeout(total=60)


class SophosError(Exception):
    """Generic error."""


class SophosAuthError(SophosError):
    """Invalid API key or insufficient permissions."""


class SophosConnectionError(SophosError):
    """Firewall not reachable."""


class SophosApiError(SophosError):
    """The firewall returned an error."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body


class SophosRestClient:
    """Access to /api/firewall-config/v1 with an API key (Bearer)."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        api_key: str,
        verify_ssl: bool,
    ) -> None:
        self._session = session
        self._base = f"https://{host}:{port}{API_BASE}"
        self._api_key = api_key
        self._ssl = None if verify_ssl else False

    async def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }
        try:
            async with self._session.request(
                method,
                self._base + path,
                json=body,
                headers=headers,
                ssl=self._ssl,
                timeout=TIMEOUT,
            ) as resp:
                text = await resp.text()
                if resp.status in (401, 403):
                    raise SophosAuthError(f"HTTP {resp.status}")
                if resp.status >= 400:
                    raise SophosApiError(resp.status, text)
                if not text.strip():
                    return None
                return await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            raise SophosConnectionError(str(err) or type(err).__name__) from err

    @staticmethod
    def _items(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, dict):
            return list(data.get("items") or [])
        return list(data or [])

    async def get_dhcp_servers_v4(self) -> list[dict[str, Any]]:
        """All DHCPv4 servers, including reservations and pools."""
        return self._items(await self._request("GET", PATH_DHCP_SERVERS_V4))

    async def get_dhcp_leases_v4(self) -> list[dict[str, Any]]:
        """Active DHCPv4 leases (static and dynamic), all pages."""
        items: list[dict[str, Any]] = []
        path = PATH_DHCP_LEASES_V4
        for _ in range(50):  # safety limit
            data = await self._request("GET", path)
            items.extend(self._items(data))
            pages = data.get("pages") if isinstance(data, dict) else None
            nxt = (pages or {}).get("nextKey") if isinstance(pages, dict) else None
            if not nxt:
                break
            path = f"{PATH_DHCP_LEASES_V4}?fromKey={quote(str(nxt), safe='')}"
        return items

    async def patch_dhcp_server_v4(self, name: str, changes: dict[str, Any]) -> Any:
        """Change fields of a DHCPv4 server (not used yet)."""
        return await self._request(
            "PATCH", f"{PATH_DHCP_SERVERS_V4}/{quote(name, safe='')}", changes
        )
