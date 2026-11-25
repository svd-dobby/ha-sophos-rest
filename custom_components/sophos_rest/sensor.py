"""DHCP sensors: reservations, active leases and free addresses."""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address
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


def _pools(server: dict[str, Any]) -> list[tuple[IPv4Address, IPv4Address]]:
    result = []
    for p in server.get("addressPools") or []:
        try:
            result.append((ip_address(p["startAddressIpv4"]), ip_address(p["endAddressIpv4"])))
        except (KeyError, ValueError):
            continue
    return result


def _in_pools(ip: str | None, pools: list[tuple[IPv4Address, IPv4Address]]) -> bool:
    try:
        a = ip_address(ip or "")
    except ValueError:
        return False
    return any(lo <= a <= hi for lo, hi in pools)


def _lease(lease: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": lease.get("clientHostName"),
        "mac": lease.get("macAddress"),
        "ip": lease.get("leasedIp"),
        "type": lease.get("leaseType"),
        "end": lease.get("leasedEnd"),
    }


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    known: set[str] = set()

    async_add_entities([DhcpLeasesSensor(coordinator), DhcpDynamicLeasesSensor(coordinator)])

    @callback
    def _add_new() -> None:
        new = [n for n in coordinator.data.dhcp_servers if n not in known]
        known.update(new)
        ents: list[SensorEntity] = []
        for n in new:
            ents.append(DhcpReservationsSensor(coordinator, n))
            ents.append(DhcpFreeAddressesSensor(coordinator, n))
        async_add_entities(ents)

    _add_new()
    entry.async_on_unload(coordinator.async_add_listener(_add_new))


class SophosEntity(CoordinatorEntity[SophosCoordinator], SensorEntity):
    """Common base: device info and naming."""

    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: SophosCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id or entry.entry_id)},
            name=entry.title,
            manufacturer="Sophos",
            model="Sophos Firewall",
        )


class _ServerSensor(SophosEntity):
    def __init__(self, coordinator: SophosCoordinator, server: str, key: str) -> None:
        super().__init__(coordinator, f"dhcp_{server}_{key}")
        self._server = server
        self._attr_translation_placeholders = {"server": server}

    @property
    def _data(self) -> dict[str, Any] | None:
        return self.coordinator.data.dhcp_servers.get(self._server)

    @property
    def available(self) -> bool:
        return super().available and self._data is not None


class DhcpReservationsSensor(_ServerSensor):
    """Number of static reservations on one DHCPv4 server, with the list as attribute."""

    _attr_translation_key = "dhcp_reservations"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:ip-network"
    _unrecorded_attributes = frozenset({"reservations"})

    def __init__(self, coordinator: SophosCoordinator, server: str) -> None:
        super().__init__(coordinator, server, "reservations")

    @property
    def native_value(self) -> int | None:
        if (s := self._data) is None:
            return None
        return len(s.get("clientReservations") or [])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        s = self._data or {}
        res = sorted(
            s.get("clientReservations") or [],
            key=lambda r: ip_address(r.get("ipv4Address") or "0.0.0.0"),
        )
        return {
            "enabled": s.get("enabled"),
            "interface": (s.get("interface") or {}).get("name"),
            "pools": [
                f"{p.get('startAddressIpv4')}-{p.get('endAddressIpv4')}"
                for p in (s.get("addressPools") or [])
            ],
            "reservations": [
                {"hostname": r.get("hostname"), "mac": r.get("macAddress"), "ip": r.get("ipv4Address")}
                for r in res
            ],
        }


class DhcpFreeAddressesSensor(_ServerSensor):
    """Free addresses in the dynamic pools of one server."""

    _attr_translation_key = "dhcp_free"
    _attr_icon = "mdi:ip-outline"

    def __init__(self, coordinator: SophosCoordinator, server: str) -> None:
        super().__init__(coordinator, server, "free")

    def _calc(self) -> tuple[int, int]:
        pools = _pools(self._data or {})
        size = sum(int(hi) - int(lo) + 1 for lo, hi in pools)
        used = sum(
            1 for lease in self.coordinator.data.dhcp_leases
            if lease.get("leaseType") == "dynamic" and _in_pools(lease.get("leasedIp"), pools)
        )
        return size, used

    @property
    def native_value(self) -> int | None:
        if self._data is None:
            return None
        size, used = self._calc()
        return max(size - used, 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        size, used = self._calc()
        return {"pool_size": size, "dynamic_in_use": used}


class DhcpLeasesSensor(SophosEntity):
    """All active leases (static and dynamic)."""

    _attr_translation_key = "dhcp_leases"
    _attr_icon = "mdi:lan-connect"
    _unrecorded_attributes = frozenset({"leases"})

    def __init__(self, coordinator: SophosCoordinator) -> None:
        super().__init__(coordinator, "dhcp_leases")

    @property
    def native_value(self) -> int:
        return len(self.coordinator.data.dhcp_leases)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        leases = self.coordinator.data.dhcp_leases
        return {
            "static": sum(1 for x in leases if x.get("leaseType") == "static"),
            "dynamic": sum(1 for x in leases if x.get("leaseType") == "dynamic"),
            "leases": [_lease(x) for x in leases],
        }


class DhcpDynamicLeasesSensor(SophosEntity):
    """Devices with a dynamic address (candidates for a static reservation)."""

    _attr_translation_key = "dhcp_dynamic_leases"
    _attr_icon = "mdi:ip-network-outline"
    _unrecorded_attributes = frozenset({"devices"})

    def __init__(self, coordinator: SophosCoordinator) -> None:
        super().__init__(coordinator, "dhcp_dynamic_leases")

    def _dyn(self) -> list[dict[str, Any]]:
        return [x for x in self.coordinator.data.dhcp_leases if x.get("leaseType") == "dynamic"]

    @property
    def native_value(self) -> int:
        return len(self._dyn())

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        dyn = sorted(self._dyn(), key=lambda x: ip_address(x.get("leasedIp") or "0.0.0.0"))
        return {"devices": [_lease(x) for x in dyn]}
