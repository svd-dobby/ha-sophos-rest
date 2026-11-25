"""Base entity: device info and naming."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import SophosCoordinator
from .snmp_coordinator import SnmpCoordinator


class SophosEntity(CoordinatorEntity[SophosCoordinator]):
    """Common base for all entities of one firewall."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: SophosCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_{key}"
        snmp = coordinator.snmp
        system = snmp.data.system if snmp is not None and snmp.data else {}
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id or entry.entry_id)},
            name=coordinator.data.hostname or entry.title,
            manufacturer="Sophos",
            model=system.get("model") or "Sophos Firewall",
            sw_version=system.get("firmware"),
            serial_number=system.get("serial"),
        )


class SophosSnmpEntity(CoordinatorEntity[SnmpCoordinator]):
    """Common base for entities fed by SNMP; same device as the REST entities."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: SnmpCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_snmp_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id or entry.entry_id)},
        )
