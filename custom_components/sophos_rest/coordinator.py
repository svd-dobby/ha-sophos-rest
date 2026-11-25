"""Coordinator: polls the firewall periodically."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
import logging
from typing import Any

from cryptography import x509

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import SophosApiError, SophosAuthError, SophosError, SophosRestClient
from .const import (
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    PATH_CERTIFICATES,
    PATH_FIREWALL_RULES_V4,
    PATH_HOTFIX_SETTINGS,
    PATH_INTERFACES,
    PATH_IPS_SETTINGS,
    PATH_LIVE_USERS,
    PATH_NAT_RULES_V4,
    PATH_SPOOF_SETTINGS,
    PATH_SYSTEM_SETTINGS,
)

_LOGGER = logging.getLogger(__name__)


@dataclass
class SophosData:
    """Snapshot of the firewall data. Optional parts are None when not readable."""

    dhcp_servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    dhcp_leases: list[dict[str, Any]] = field(default_factory=list)
    hostname: str | None = None
    firewall_rules: dict[str, dict[str, Any]] | None = None
    nat_rules: dict[str, dict[str, Any]] | None = None
    interfaces: dict[str, dict[str, Any]] | None = None
    live_users: list[dict[str, Any]] | None = None
    certificates: dict[str, dict[str, Any]] | None = None
    ips: dict[str, Any] | None = None
    spoof: dict[str, Any] | None = None
    hotfix: dict[str, Any] | None = None
    unavailable: dict[str, str] = field(default_factory=dict)


def _by_key(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(i[key]): i for i in items if i.get(key)}


def _cert_info(item: dict[str, Any]) -> dict[str, Any]:
    """Name and validity of a certificate; the certificate itself is not kept."""
    info: dict[str, Any] = {"name": item.get("name"), "id": item.get("id")}
    try:
        pem = base64.b64decode(item.get("certificate") or "")
        cert = x509.load_pem_x509_certificate(pem)
        info["not_after"] = cert.not_valid_after_utc
        info["not_before"] = cert.not_valid_before_utc
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
    except (ValueError, TypeError) as err:
        _LOGGER.debug("Cannot parse certificate %s: %s", item.get("name"), err)
    return info


class SophosCoordinator(DataUpdateCoordinator[SophosData]):
    """One coordinator per firewall."""

    config_entry: ConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, client: SophosRestClient
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=DEFAULT_SCAN_INTERVAL,
        )
        self.client = client

    async def _optional(self, data: SophosData, key: str, coro: Any) -> Any:
        """Run an optional request; a missing permission or path only disables that part."""
        try:
            return await coro
        except SophosApiError as err:
            if key not in data.unavailable:
                _LOGGER.debug("Part %s not available: %s", key, err)
            data.unavailable[key] = f"HTTP {err.status}"
            return None

    async def _async_update_data(self) -> SophosData:
        c = self.client
        data = SophosData()
        try:
            servers = await c.get_dhcp_servers_v4()
            data.dhcp_servers = {s["name"]: s for s in servers if s.get("name")}
            data.dhcp_leases = await c.get_dhcp_leases_v4()

            settings = await self._optional(data, "system", c.get(PATH_SYSTEM_SETTINGS))
            data.hostname = (settings or {}).get("hostname")

            rules = await self._optional(data, "firewall_rules", c.get_all(PATH_FIREWALL_RULES_V4))
            data.firewall_rules = None if rules is None else _by_key(rules, "id")
            nat = await self._optional(data, "nat_rules", c.get_all(PATH_NAT_RULES_V4))
            data.nat_rules = None if nat is None else _by_key(nat, "id")
            ifaces = await self._optional(data, "interfaces", c.get_all(PATH_INTERFACES))
            data.interfaces = None if ifaces is None else _by_key(ifaces, "name")
            data.live_users = await self._optional(data, "live_users", c.get_all(PATH_LIVE_USERS))
            certs = await self._optional(data, "certificates", c.get_all(PATH_CERTIFICATES))
            data.certificates = (
                None if certs is None
                else {i["id"]: _cert_info(i) for i in certs if i.get("id")}
            )
            data.ips = await self._optional(data, "ips", c.get(PATH_IPS_SETTINGS))
            data.spoof = await self._optional(data, "spoof", c.get(PATH_SPOOF_SETTINGS))
            data.hotfix = await self._optional(data, "hotfix", c.get(PATH_HOTFIX_SETTINGS))
        except SophosAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except SophosError as err:
            raise UpdateFailed(str(err)) from err
        return data


def days_until(moment: datetime | None, now: datetime) -> int | None:
    """Whole days from now until moment (negative when expired)."""
    if moment is None:
        return None
    return (moment - now).days
