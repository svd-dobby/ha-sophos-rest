"""Sensors: DHCP, live users and certificate expiry."""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address
from typing import Any

from datetime import timedelta

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.const import (
    PERCENTAGE,
    REVOLUTIONS_PER_MINUTE,
    EntityCategory,
    UnitOfInformation,
    UnitOfPower,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from . import SophosConfigEntry
from .coordinator import SophosCoordinator, days_until
from .entity import (
    GROUP_DHCP,
    GROUP_INTERFACES,
    GROUP_LICENSES,
    GROUP_SECURITY,
    SophosEntity,
    SophosSnmpEntity,
)
from .snmp_coordinator import SnmpCoordinator


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

    snmp: SnmpCoordinator | None = coordinator.snmp
    if snmp is None:
        return
    snmp_known: set[str] = set()

    @callback
    def _add_snmp() -> None:
        if snmp.data is None:
            return
        ents: list[SensorEntity] = []
        for key in SYSTEM_SENSORS:
            if key not in snmp_known and snmp.data.system.get(SYSTEM_SENSORS[key]["field"]) is not None:
                snmp_known.add(key)
                ents.append(SnmpSystemSensor(snmp, key, coordinator.data.hostname))
        host = coordinator.data.hostname
        for key in snmp.data.licenses:
            if (k := f"lic:{key}") not in snmp_known:
                snmp_known.add(k)
                ents.append(LicenseSensor(snmp, key, host))
        for label in snmp.data.poe:
            if (k := f"poe:{label}") not in snmp_known:
                snmp_known.add(k)
                ents.append(PoeSensor(snmp, label, host))
        for idx in snmp.data.fans:
            if (k := f"fan:{idx}") not in snmp_known:
                snmp_known.add(k)
                ents.append(FanSensor(snmp, idx, host))
        for name in snmp_interfaces(coordinator, snmp):
            for direction in ("in", "out"):
                if (k := f"if:{name}:{direction}") not in snmp_known:
                    snmp_known.add(k)
                    ents.append(SnmpTrafficSensor(snmp, name, direction, coordinator.data.hostname))
        if ents:
            async_add_entities(ents)

    _add_snmp()
    entry.async_on_unload(snmp.async_add_listener(_add_snmp))


class SophosSensor(SophosEntity, SensorEntity):
    """Base for the sensors."""

    _attr_state_class = SensorStateClass.MEASUREMENT


class _ServerSensor(SophosSensor):
    _group = GROUP_DHCP

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

    _group = GROUP_DHCP
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

    _group = GROUP_DHCP
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

    _group = GROUP_SECURITY
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


def snmp_interfaces(rest: SophosCoordinator, snmp: SnmpCoordinator) -> list[str]:
    """SNMP interfaces to expose: those known to the REST API, else the Ethernet ones."""
    if snmp.data is None:
        return []
    names = set((rest.data.interfaces or {}).keys())
    if names:
        return [n for n in snmp.data.interfaces if n in names]
    return [n for n, i in snmp.data.interfaces.items() if i.get("type") == 6]


SYSTEM_SENSORS: dict[str, dict[str, Any]] = {
    "cpu": {"field": "cpu_percent", "unit": PERCENTAGE, "icon": "mdi:cpu-64-bit"},
    "memory": {"field": "memory_percent", "unit": PERCENTAGE, "icon": "mdi:memory"},
    "swap": {"field": "swap_percent", "unit": PERCENTAGE, "icon": "mdi:memory", "diag": True},
    "disk": {"field": "disk_percent", "unit": PERCENTAGE, "icon": "mdi:harddisk"},
    "cpu_temperature": {"field": "cpu_temperature", "unit": UnitOfTemperature.CELSIUS,
                        "class": SensorDeviceClass.TEMPERATURE},
    "npu_temperature": {"field": "npu_temperature", "unit": UnitOfTemperature.CELSIUS,
                        "class": SensorDeviceClass.TEMPERATURE},
    "last_boot": {"field": "uptime_seconds", "class": SensorDeviceClass.TIMESTAMP, "diag": True},
    "firmware": {"field": "firmware", "icon": "mdi:package-variant", "diag": True, "text": True},
    "ips_version": {"field": "ips_version", "icon": "mdi:shield-sync", "diag": True, "text": True},
    "webcat_version": {"field": "webcat_version", "icon": "mdi:web", "diag": True, "text": True},
}


class SnmpSystemSensor(SophosSnmpEntity, SensorEntity):
    """A system value from the SNMP agent."""

    def __init__(self, coordinator: SnmpCoordinator, key: str, hostname: str | None) -> None:
        super().__init__(coordinator, key, hostname)
        spec = SYSTEM_SENSORS[key]
        self._field = spec["field"]
        self._attr_translation_key = key
        self._attr_native_unit_of_measurement = spec.get("unit")
        self._attr_device_class = spec.get("class")
        if "icon" in spec:
            self._attr_icon = spec["icon"]
        if spec.get("diag"):
            self._attr_entity_category = EntityCategory.DIAGNOSTIC
        if not spec.get("text") and spec.get("class") != SensorDeviceClass.TIMESTAMP:
            self._attr_state_class = SensorStateClass.MEASUREMENT
        self._boot = None

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.data is not None and (
            self.coordinator.data.system.get(self._field) is not None
        )

    @property
    def native_value(self) -> Any:
        value = self.coordinator.data.system.get(self._field) if self.coordinator.data else None
        if self._field == "uptime_seconds" and value is not None:
            # Last boot, rounded to the minute so the state does not change every poll.
            boot = (dt_util.utcnow() - timedelta(seconds=value)).replace(second=0, microsecond=0)
            if self._boot is None or abs((boot - self._boot).total_seconds()) > 120:
                self._boot = boot
            return self._boot
        return value


class SnmpTrafficSensor(SophosSnmpEntity, SensorEntity):
    """Bytes received or sent on an interface (64-bit counter)."""

    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfInformation.BYTES
    _attr_suggested_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_suggested_display_precision = 2
    _group = GROUP_INTERFACES

    def __init__(self, coordinator: SnmpCoordinator, name: str, direction: str, hostname: str | None) -> None:
        super().__init__(coordinator, f"interface_{name}_{direction}", hostname)
        self._name = name
        self._field = f"{direction}_octets"
        self._attr_translation_key = f"traffic_{direction}"
        self._attr_translation_placeholders = {"name": name}
        self._attr_icon = "mdi:download-network" if direction == "in" else "mdi:upload-network"

    @property
    def _iface(self) -> dict[str, Any] | None:
        return self.coordinator.data.interfaces.get(self._name) if self.coordinator.data else None

    @property
    def available(self) -> bool:
        return super().available and self._iface is not None and self._iface.get(self._field) is not None

    @property
    def native_value(self) -> int | None:
        return (self._iface or {}).get(self._field)


LICENSE_NAMES = {
    "base_firewall": "Base Firewall",
    "network_protection": "Network Protection",
    "web_protection": "Web Protection",
    "email_protection": "Email Protection",
    "web_server_protection": "Web Server Protection",
    "zero_day_protection": "Zero-Day Protection",
    "enhanced_support": "Enhanced Support",
    "enhanced_plus_support": "Enhanced Plus Support",
    "central_orchestration": "Central Orchestration",
}


class LicenseSensor(SophosSnmpEntity, SensorEntity):
    """Days until a licence (subscription) expires; status as attribute."""

    _group = GROUP_LICENSES
    _attr_translation_key = "license"
    _attr_icon = "mdi:license"
    _attr_native_unit_of_measurement = UnitOfTime.DAYS
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: SnmpCoordinator, key: str, hostname: str | None) -> None:
        super().__init__(coordinator, f"license_{key}", hostname)
        self._key = key
        self._attr_translation_placeholders = {"name": LICENSE_NAMES.get(key, key)}
        lic = coordinator.data.licenses.get(key, {}) if coordinator.data else {}
        # Subscriptions that are not active are not useful by default.
        self._attr_entity_registry_enabled_default = lic.get("state") in ("subscribed", "evaluating")

    @property
    def _lic(self) -> dict[str, Any] | None:
        return self.coordinator.data.licenses.get(self._key) if self.coordinator.data else None

    @property
    def available(self) -> bool:
        return super().available and self._lic is not None

    @property
    def native_value(self) -> int | None:
        lic = self._lic or {}
        expires = lic.get("expires")
        if expires is None:
            return None
        return (expires - dt_util.now().date()).days

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        lic = self._lic or {}
        exp = lic.get("expires")
        return {"status": lic.get("state"), "expires": exp.isoformat() if exp else None}


class PoeSensor(SophosSnmpEntity, SensorEntity):
    """Power drawn by a PoE port."""

    _group = GROUP_INTERFACES
    _attr_translation_key = "poe_power"
    _attr_device_class = SensorDeviceClass.POWER
    _attr_native_unit_of_measurement = UnitOfPower.WATT
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: SnmpCoordinator, label: str, hostname: str | None) -> None:
        super().__init__(coordinator, f"poe_{label}", hostname)
        self._label = label
        self._attr_translation_placeholders = {"name": label}

    @property
    def _poe(self) -> dict[str, Any] | None:
        return self.coordinator.data.poe.get(self._label) if self.coordinator.data else None

    @property
    def available(self) -> bool:
        return super().available and self._poe is not None

    @property
    def native_value(self) -> float | None:
        return (self._poe or {}).get("power_w")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        p = self._poe or {}
        return {"enabled": p.get("enabled"), "limit_w": p.get("limit_w")}


class FanSensor(SophosSnmpEntity, SensorEntity):
    """Fan speed."""

    _attr_translation_key = "fan"
    _attr_icon = "mdi:fan"
    _attr_native_unit_of_measurement = REVOLUTIONS_PER_MINUTE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SnmpCoordinator, index: str, hostname: str | None) -> None:
        super().__init__(coordinator, f"fan_{index}", hostname)
        self._index = index
        self._attr_translation_placeholders = {"index": index}

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.data is not None and (
            self._index in self.coordinator.data.fans
        )

    @property
    def native_value(self) -> int | None:
        return self.coordinator.data.fans.get(self._index) if self.coordinator.data else None
