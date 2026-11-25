"""Sensors: DHCP, live users and certificate expiry."""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from . import SophosConfigEntry
from .coordinator import SophosCoordinator, days_until
from .entity import SophosEntity


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

    first: list[SensorEntity] = [DhcpLeasesSensor(coordinator), DhcpDynamicLeasesSensor(coordinator)]
    if coordinator.data.live_users is not None:
        first.append(LiveUsersSensor(coordinator))
    async_add_entities(first)

    @callback
    def _add_new() -> None:
        data = coordinator.data
        ents: list[SensorEntity] = []
        for n in data.dhcp_servers:
            if (k := f"dhcp:{n}") not in known:
                known.add(k)
                ents.append(DhcpReservationsSensor(coordinator, n))
                ents.append(DhcpFreeAddressesSensor(coordinator, n))
        for cid in data.certificates or {}:
            if (k := f"cert:{cid}") not in known:
                known.add(k)
                ents.append(CertificateExpirySensor(coordinator, cid))
        if ents:
            async_add_entities(ents)

    _add_new()
    entry.async_on_unload(coordinator.async_add_listener(_add_new))


class SophosSensor(SophosEntity, SensorEntity):
    """Base for the sensors."""

    _attr_state_class = SensorStateClass.MEASUREMENT


class _ServerSensor(SophosSensor):
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


class DhcpLeasesSensor(SophosSensor):
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


class DhcpDynamicLeasesSensor(SophosSensor):
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


class LiveUsersSensor(SophosSensor):
    """Users currently logged in on the firewall."""

    _attr_translation_key = "live_users"
    _attr_icon = "mdi:account-network"
    _unrecorded_attributes = frozenset({"users"})

    def __init__(self, coordinator: SophosCoordinator) -> None:
        super().__init__(coordinator, "live_users")

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.data.live_users is not None

    @property
    def native_value(self) -> int | None:
        users = self.coordinator.data.live_users
        return None if users is None else len(users)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "users": [
                {
                    "user": u.get("userName"),
                    "ip": u.get("ipv4Address"),
                    "client": u.get("clientType"),
                    "since": u.get("loggedInTime"),
                }
                for u in self.coordinator.data.live_users or []
            ]
        }


class CertificateExpirySensor(SophosSensor):
    """Days until a certificate expires."""

    _attr_translation_key = "certificate_expiry"
    _attr_icon = "mdi:certificate"
    _attr_native_unit_of_measurement = UnitOfTime.DAYS
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SophosCoordinator, cert_id: str) -> None:
        super().__init__(coordinator, f"certificate_{cert_id}_expiry")
        self._id = cert_id
        info = (coordinator.data.certificates or {}).get(cert_id, {})
        self._attr_translation_placeholders = {"name": info.get("name") or cert_id}

    @property
    def _info(self) -> dict[str, Any] | None:
        return (self.coordinator.data.certificates or {}).get(self._id)

    @property
    def available(self) -> bool:
        return super().available and self._info is not None and "not_after" in self._info

    @property
    def native_value(self) -> int | None:
        info = self._info or {}
        return days_until(info.get("not_after"), dt_util.utcnow())

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        info = self._info or {}
        na = info.get("not_after")
        return {
            "expires": na.isoformat() if na else None,
            "subject": info.get("subject"),
            "issuer": info.get("issuer"),
        }
