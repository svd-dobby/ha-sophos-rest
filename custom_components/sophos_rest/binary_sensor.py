"""Binary sensors: rules, interfaces and protection features (read-only)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import SophosConfigEntry
from .coordinator import SophosCoordinator, SophosData
from .entity import (
    GROUP_FIREWALL_RULES,
    GROUP_INTERFACES,
    GROUP_NAT_RULES,
    GROUP_SECURITY,
    GROUP_SERVICES,
    GROUP_VPN,
    SophosEntity,
    SophosSnmpEntity,
)
from .sensor import snmp_interfaces
from .snmp_coordinator import SnmpCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    known: set[str] = set()

    @callback
    def _add_new() -> None:
        data = coordinator.data
        ents: list[BinarySensorEntity] = []
        for rid in data.firewall_rules or {}:
            if (k := f"fw:{rid}") not in known:
                known.add(k)
                ents.append(RuleSensor(coordinator, rid, "firewall"))
        for rid in data.nat_rules or {}:
            if (k := f"nat:{rid}") not in known:
                known.add(k)
                ents.append(RuleSensor(coordinator, rid, "nat"))
        for name in data.interfaces or {}:
            if (k := f"if:{name}") not in known:
                known.add(k)
                ents.append(InterfaceSensor(coordinator, name))
        for key, getter in FEATURES.items():
            if key not in known and getter(data) is not None:
                known.add(key)
                ents.append(FeatureSensor(coordinator, key))
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
        host = coordinator.data.hostname
        ents: list[BinarySensorEntity] = []
        for n in snmp_interfaces(coordinator, snmp):
            if (k := f"link:{n}") not in snmp_known:
                snmp_known.add(k)
                ents.append(LinkSensor(snmp, n, host))
        for key in snmp.data.services:
            if (k := f"svc:{key}") not in snmp_known:
                snmp_known.add(k)
                ents.append(ServiceSensor(snmp, key, host))
        for name in snmp.data.vpn:
            if (k := f"vpn:{name}") not in snmp_known:
                snmp_known.add(k)
                ents.append(VpnSensor(snmp, name, host))
        if ents:
            async_add_entities(ents)

    _add_snmp()
    entry.async_on_unload(snmp.async_add_listener(_add_snmp))


class SophosBinarySensor(SophosEntity, BinarySensorEntity):
    """Base for the binary sensors."""


class RuleSensor(SophosBinarySensor):
    """A firewall or NAT rule: on when the rule is enabled."""

    _attr_icon = "mdi:wall-fire"

    def __init__(self, coordinator: SophosCoordinator, rule_id: str, kind: str) -> None:
        self._group = GROUP_FIREWALL_RULES if kind == "firewall" else GROUP_NAT_RULES
        super().__init__(coordinator, f"{kind}_rule_{rule_id}")
        self._id = rule_id
        self._kind = kind
        self._attr_translation_key = f"{kind}_rule"
        rule = self._rules.get(rule_id, {}) if self._rules else {}
        self._attr_translation_placeholders = {"name": rule.get("name") or rule_id}

    @property
    def _rules(self) -> dict[str, dict[str, Any]] | None:
        d = self.coordinator.data
        return d.firewall_rules if self._kind == "firewall" else d.nat_rules

    @property
    def _rule(self) -> dict[str, Any] | None:
        return (self._rules or {}).get(self._id)

    @property
    def available(self) -> bool:
        return super().available and self._rule is not None

    @property
    def is_on(self) -> bool | None:
        rule = self._rule
        return None if rule is None else bool(rule.get("enabled"))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        rule = self._rule or {}
        attrs = {"name": rule.get("name"), "description": rule.get("description")}
        if self._kind == "firewall":
            attrs["action"] = rule.get("action")
            attrs["rule_type"] = rule.get("ruleType")
        return attrs


class InterfaceSensor(SophosBinarySensor):
    """A network interface: on when the interface is enabled (no live link state in the API)."""

    _attr_translation_key = "interface"
    _attr_icon = "mdi:ethernet"
    _group = GROUP_INTERFACES
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SophosCoordinator, name: str) -> None:
        super().__init__(coordinator, f"interface_{name}")
        self._name = name
        self._attr_translation_placeholders = {"name": name}

    @property
    def _iface(self) -> dict[str, Any] | None:
        return (self.coordinator.data.interfaces or {}).get(self._name)

    @property
    def available(self) -> bool:
        return super().available and self._iface is not None

    @property
    def is_on(self) -> bool | None:
        i = self._iface
        return None if i is None else bool(i.get("enabled"))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        i = self._iface or {}
        return {
            "hardware": i.get("hardwareName"),
            "type": i.get("type"),
            "zone": (i.get("zone") or {}).get("name"),
            "member_of": i.get("memberOf"),
            "ipv4": i.get("ipv4"),
            "mtu": i.get("mtu"),
        }


FEATURES: dict[str, Callable[[SophosData], bool | None]] = {
    "ips": lambda d: None if d.ips is None else bool(d.ips.get("enabled")),
    "spoof_protection": lambda d: None if d.spoof is None else bool(d.spoof.get("spoofProtection")),
    "hotfix_auto": lambda d: None if d.hotfix is None else bool(d.hotfix.get("enabled")),
}


class FeatureSensor(SophosBinarySensor):
    """A protection feature that is on or off."""

    _attr_icon = "mdi:shield-check"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _group = GROUP_SECURITY

    def __init__(self, coordinator: SophosCoordinator, key: str) -> None:
        super().__init__(coordinator, f"feature_{key}")
        self._key = key
        self._attr_translation_key = key

    @property
    def available(self) -> bool:
        return super().available and FEATURES[self._key](self.coordinator.data) is not None

    @property
    def is_on(self) -> bool | None:
        return FEATURES[self._key](self.coordinator.data)


class LinkSensor(SophosSnmpEntity, BinarySensorEntity):
    """Live link state of an interface (SNMP ifOperStatus)."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "link"
    _group = GROUP_INTERFACES

    def __init__(self, coordinator: SnmpCoordinator, name: str, hostname: str | None) -> None:
        super().__init__(coordinator, f"interface_{name}_link", hostname)
        self._name = name
        self._attr_translation_placeholders = {"name": name}

    @property
    def _iface(self) -> dict[str, Any] | None:
        return self.coordinator.data.interfaces.get(self._name) if self.coordinator.data else None

    @property
    def available(self) -> bool:
        return super().available and self._iface is not None

    @property
    def is_on(self) -> bool | None:
        i = self._iface
        return None if i is None else bool(i.get("link_up"))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        i = self._iface or {}
        return {"speed_mbps": i.get("speed_mbps"), "admin_up": i.get("admin_up")}


SERVICE_NAMES = {
    "pop3": "POP3", "imap": "IMAP", "smtp": "SMTP", "ftp": "FTP", "http_proxy": "HTTP proxy",
    "antivirus": "Antivirus", "antispam": "Anti-spam", "dns": "DNS", "ha_service": "HA service",
    "ips": "IPS", "apache": "Apache", "ntp": "NTP", "tomcat": "Tomcat", "ssl_vpn": "SSL VPN",
    "ipsec_vpn": "IPsec VPN", "database": "Database", "network": "Network", "garner": "Garner",
    "dynamic_routing": "Dynamic routing", "ssh": "SSH", "dgd": "DGD",
}


class ServiceSensor(SophosSnmpEntity, BinarySensorEntity):
    """A firewall service: on when running."""

    _group = GROUP_SERVICES
    _attr_device_class = BinarySensorDeviceClass.RUNNING
    _attr_translation_key = "service"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SnmpCoordinator, key: str, hostname: str | None) -> None:
        super().__init__(coordinator, f"service_{key}", hostname)
        self._key = key
        self._attr_translation_placeholders = {"name": SERVICE_NAMES.get(key, key)}
        svc = coordinator.data.services.get(key, {}) if coordinator.data else {}
        # Services that were never started (untouched) are not useful by default.
        self._attr_entity_registry_enabled_default = svc.get("state") != "untouched"

    @property
    def _svc(self) -> dict[str, Any] | None:
        return self.coordinator.data.services.get(self._key) if self.coordinator.data else None

    @property
    def available(self) -> bool:
        return super().available and self._svc is not None

    @property
    def is_on(self) -> bool | None:
        svc = self._svc
        return None if svc is None else svc.get("state") == "running"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"state": (self._svc or {}).get("state")}


class VpnSensor(SophosSnmpEntity, BinarySensorEntity):
    """An IPsec connection: on when (partially) active."""

    _group = GROUP_VPN
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "vpn"
    _attr_icon = "mdi:vpn"

    def __init__(self, coordinator: SnmpCoordinator, name: str, hostname: str | None) -> None:
        super().__init__(coordinator, f"vpn_{name}", hostname)
        self._name = name
        self._attr_translation_placeholders = {"name": name}

    @property
    def _vpn(self) -> dict[str, Any] | None:
        return self.coordinator.data.vpn.get(self._name) if self.coordinator.data else None

    @property
    def available(self) -> bool:
        return super().available and self._vpn is not None

    @property
    def is_on(self) -> bool | None:
        v = self._vpn
        return None if v is None else v.get("status") in ("active", "partially_active")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        v = self._vpn or {}
        return {k: v.get(k) for k in ("status", "activated", "tunnels", "policy", "type", "interface")}
