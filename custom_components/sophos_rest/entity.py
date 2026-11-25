"""Base entities: device info and grouping into sub-devices."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import SophosCoordinator
from .snmp_coordinator import SnmpCoordinator

# Sub-devices below the main firewall device, like a hub with child devices.
# None means the main device itself.
GROUP_DHCP = "dhcp"
GROUP_FIREWALL_RULES = "firewall_rules"
GROUP_NAT_RULES = "nat_rules"
GROUP_INTERFACES = "interfaces"
GROUP_SECURITY = "security"


def base_identifier(entry: ConfigEntry) -> str:
    """Identifier of the main device."""
    return entry.unique_id or entry.entry_id


def main_device_info(
    entry: ConfigEntry, hostname: str | None, system: dict[str, Any]
) -> DeviceInfo:
    """The main device: the firewall itself."""
    return DeviceInfo(
        identifiers={(DOMAIN, base_identifier(entry))},
        name=hostname or entry.title,
        manufacturer="Sophos",
        model=system.get("model") or "Sophos Firewall",
        sw_version=system.get("firmware"),
        serial_number=system.get("serial"),
    )


def group_device_info(
    entry: ConfigEntry, group: str | None, hostname: str | None
) -> DeviceInfo:
    """Device info for a group; a sub-device is linked to the main device."""
    base = base_identifier(entry)
    if group is None:
        return DeviceInfo(identifiers={(DOMAIN, base)})
    return DeviceInfo(
        identifiers={(DOMAIN, f"{base}_{group}")},
        via_device=(DOMAIN, base),
        manufacturer="Sophos",
        model="Sophos Firewall",
        translation_key=group,
        translation_placeholders={"host": hostname or entry.title},
    )


class SophosEntity(CoordinatorEntity[SophosCoordinator]):
    """Base for entities fed by the REST API."""

    _attr_has_entity_name = True
    _group: str | None = None

    def __init__(self, coordinator: SophosCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_{key}"
        self._attr_device_info = group_device_info(
            entry, self._group, coordinator.data.hostname
        )


class SophosSnmpEntity(CoordinatorEntity[SnmpCoordinator]):
    """Base for entities fed by SNMP."""

    _attr_has_entity_name = True
    _group: str | None = None

    def __init__(
        self, coordinator: SnmpCoordinator, key: str, hostname: str | None
    ) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_snmp_{key}"
        self._attr_device_info = group_device_info(entry, self._group, hostname)
