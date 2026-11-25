"""Sensoren: per DHCP-server het aantal vaste reserveringen."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SophosConfigEntry
from .const import DOMAIN
from .coordinator import SophosCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    known: set[str] = set()

    @callback
    def _add_new() -> None:
        new = [n for n in coordinator.data.dhcp_servers if n not in known]
        known.update(new)
        async_add_entities(DhcpReservationsSensor(coordinator, n) for n in new)

    _add_new()
    entry.async_on_unload(coordinator.async_add_listener(_add_new))


class DhcpReservationsSensor(CoordinatorEntity[SophosCoordinator], SensorEntity):
    """Aantal vaste reserveringen op één DHCPv4-server."""

    _attr_has_entity_name = True
    _attr_translation_key = "dhcp_reservations"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:ip-network"

    def __init__(self, coordinator: SophosCoordinator, server: str) -> None:
        super().__init__(coordinator)
        self._server = server
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_dhcp_{server}_reservations"
        self._attr_translation_placeholders = {"server": server}
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id or entry.entry_id)},
            name=entry.title,
            manufacturer="Sophos",
            model="Sophos Firewall",
        )

    @property
    def _data(self) -> dict[str, Any] | None:
        return self.coordinator.data.dhcp_servers.get(self._server)

    @property
    def available(self) -> bool:
        return super().available and self._data is not None

    @property
    def native_value(self) -> int | None:
        if (s := self._data) is None:
            return None
        return len(s.get("clientReservations") or [])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        s = self._data or {}
        return {
            "enabled": s.get("enabled"),
            "interface": (s.get("interface") or {}).get("name"),
            "pools": [
                f"{p.get('startAddressIpv4')}-{p.get('endAddressIpv4')}"
                for p in (s.get("addressPools") or [])
            ],
        }
