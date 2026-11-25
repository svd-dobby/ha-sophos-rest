"""Coordinator: haalt periodiek de gegevens op."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import SophosAuthError, SophosError, SophosRestClient
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


@dataclass
class SophosData:
    """Momentopname van de firewall."""

    dhcp_servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    dhcp_leases: list[dict[str, Any]] = field(default_factory=list)


class SophosCoordinator(DataUpdateCoordinator[SophosData]):
    """Eén coordinator per firewall."""

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

    async def _async_update_data(self) -> SophosData:
        try:
            servers = await self.client.get_dhcp_servers_v4()
            leases = await self.client.get_dhcp_leases_v4()
        except SophosAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except SophosError as err:
            raise UpdateFailed(str(err)) from err
        return SophosData(
            dhcp_servers={s["name"]: s for s in servers if s.get("name")},
            dhcp_leases=leases,
        )
