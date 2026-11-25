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
GROUP_SERVICES = "services"
GROUP_LICENSES = "licenses"
GROUP_VPN = "vpn"
GROUPS = (
    GROUP_DHCP,
    GROUP_FIREWALL_RULES,
    GROUP_NAT_RULES,
    GROUP_INTERFACES,
    GROUP_SECURITY,
    GROUP_SERVICES,
    GROUP_LICENSES,
    GROUP_VPN,
)


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


def group_identifier(entry: ConfigEntry, group: str | None) -> str:
    """Identifier of the main device (group None) or a sub-device."""
    base = base_identifier(entry)
    return base if group is None else f"{base}_{group}"


def group_device_info(
    entry: ConfigEntry, group: str | None, hostname: str | None
) -> DeviceInfo:
    """Device info for an entity. The devices themselves (names, link to the
    main device) are created in async_setup_entry."""
    return DeviceInfo(identifiers={(DOMAIN, group_identifier(entry, group))})


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
