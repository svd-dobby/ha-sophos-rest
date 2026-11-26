"""Device trackers: one per device the DHCP server knows (reservation or lease).

Like router integrations: home = the device has an active DHCP lease. IP, MAC and
name come from the firewall, so other integrations (for example Home Security
Assistant) can match names, hostnames and MAC addresses. IP and MAC are not
stored in the recorder history.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from . import SophosConfigEntry
from .coordinator import SophosCoordinator


def _mac(value: Any) -> str:
    return str(value or "").strip().upper().replace("-", ":")


def known_devices(coordinator: SophosCoordinator) -> dict[str, dict[str, Any]]:
    """All devices by MAC: reservations first, then active leases."""
    data = coordinator.data
    devices: dict[str, dict[str, Any]] = {}
    for server, srv in data.dhcp_servers.items():
        for r in srv.get("clientReservations") or []:
            if mac := _mac(r.get("macAddress")):
                devices[mac] = {
                    "name": r.get("hostname"),
                    "reserved_ip": r.get("ipv4Address"),
                    "server": server,
                }
    for lease in data.dhcp_leases or []:
        if not (mac := _mac(lease.get("macAddress"))):
            continue
        dev = devices.setdefault(mac, {})
        dev["lease_ip"] = lease.get("leasedIp")
        dev["client_hostname"] = lease.get("clientHostName") or None
        dev["lease_type"] = lease.get("leaseType")
        dev["lease_end"] = lease.get("leasedEnd")
    return devices


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    known: set[str] = set()

    @callback
    def _add_new() -> None:
        # Only when the DHCP part is readable (Network permission).
        if not coordinator.data.dhcp_servers and coordinator.data.dhcp_leases is None:
            return
        new = [
            SophosDeviceTracker(coordinator, mac)
            for mac in known_devices(coordinator)
            if mac not in known
        ]
        known.update(t.mac_address for t in new)
        if new:
            async_add_entities(new)

    _add_new()
    entry.async_on_unload(coordinator.async_add_listener(_add_new))


class SophosDeviceTracker(CoordinatorEntity[SophosCoordinator], ScannerEntity):
    """A device on the LAN, seen through the DHCP server of the firewall."""

    _attr_has_entity_name = False
    _unrecorded_attributes = frozenset(
        {"ip", "mac", "host_name", "reserved_ip", "lease_end"}
    )

    def __init__(self, coordinator: SophosCoordinator, mac: str) -> None:
        super().__init__(coordinator)
        self._mac = mac
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_tracker_{mac.replace(':', '').lower()}"
        info = self._info
        label = info.get("name") or info.get("client_hostname") or mac
        self._attr_name = label
        host = coordinator.data.hostname or "sophos"
        self.entity_id = f"device_tracker.{slugify(f'{host} {label}')}"

    @property
    def _info(self) -> dict[str, Any]:
        return known_devices(self.coordinator).get(self._mac, {})

    @property
    def entity_registry_enabled_default(self) -> bool:
        return True

    @property
    def source_type(self) -> SourceType:
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        return self._info.get("lease_ip") is not None

    @property
    def mac_address(self) -> str:
        return self._mac

    @property
    def ip_address(self) -> str | None:
        info = self._info
        return info.get("lease_ip") or info.get("reserved_ip")

    @property
    def hostname(self) -> str | None:
        info = self._info
        return info.get("client_hostname") or info.get("name")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        info = self._info
        return {
            "reservation": info.get("name"),
            "reserved_ip": info.get("reserved_ip"),
            "dhcp_server": info.get("server"),
            "lease_type": info.get("lease_type"),
            "lease_end": info.get("lease_end"),
        }
