"""Coordinator for live data over SNMP v2c (read-only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, SNMP_SCAN_INTERVAL
from .snmp import SnmpClient, SnmpError, table

_LOGGER = logging.getLogger(__name__)

# SOPHOS-XG-MIB (sfosXGMIB), base 1.3.6.1.4.1.2604.5.1
_SFOS = "1.3.6.1.4.1.2604.5.1"
SYSTEM_OIDS: dict[str, str] = {
    "name": f"{_SFOS}.1.1.0",
    "model": f"{_SFOS}.1.2.0",
    "firmware": f"{_SFOS}.1.3.0",
    "serial": f"{_SFOS}.1.4.0",
    "webcat_version": f"{_SFOS}.1.5.0",
    "ips_version": f"{_SFOS}.1.6.0",
    "uptime": f"{_SFOS}.2.2.0",
    "disk_percent": f"{_SFOS}.2.4.2.0",
    "memory_percent": f"{_SFOS}.2.5.2.0",
    "swap_percent": f"{_SFOS}.2.5.4.0",
    "disk_capacity": f"{_SFOS}.2.4.1.0",
    "memory_capacity": f"{_SFOS}.2.5.1.0",
    "swap_capacity": f"{_SFOS}.2.5.3.0",
    "http_hits": f"{_SFOS}.2.7.0",
    "smtp_hits": f"{_SFOS}.2.9.3.0",
    "npu_temperature": f"{_SFOS}.9.1.0",
    "cpu_temperature": f"{_SFOS}.9.2.0",
}
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"

# Service states (sfosXGServiceStatus, .3.x): ServiceStatsType.
SERVICES: dict[str, str] = {
    "pop3": f"{_SFOS}.3.1.0", "imap": f"{_SFOS}.3.2.0", "smtp": f"{_SFOS}.3.3.0",
    "ftp": f"{_SFOS}.3.4.0", "http_proxy": f"{_SFOS}.3.5.0", "antivirus": f"{_SFOS}.3.6.0",
    "antispam": f"{_SFOS}.3.7.0", "dns": f"{_SFOS}.3.8.0", "ha_service": f"{_SFOS}.3.9.0",
    "ips": f"{_SFOS}.3.10.0", "apache": f"{_SFOS}.3.11.0", "ntp": f"{_SFOS}.3.12.0",
    "tomcat": f"{_SFOS}.3.13.0", "ssl_vpn": f"{_SFOS}.3.14.0", "ipsec_vpn": f"{_SFOS}.3.15.0",
    "database": f"{_SFOS}.3.16.0", "network": f"{_SFOS}.3.17.0", "garner": f"{_SFOS}.3.18.0",
    "dynamic_routing": f"{_SFOS}.3.19.0", "ssh": f"{_SFOS}.3.20.0", "dgd": f"{_SFOS}.3.21.0",
}
SERVICE_STATES = ("untouched", "stopped", "initializing", "running", "exiting", "dead", "frozen", "unregistered")
SERVICE_RUNNING = 3

# Licences (sfosXGLicenseDetails, .5.x): status and expiry date per subscription.
LICENSES: dict[str, int] = {
    "base_firewall": 1, "network_protection": 2, "web_protection": 3, "email_protection": 4,
    "web_server_protection": 5, "zero_day_protection": 6, "enhanced_support": 7,
    "enhanced_plus_support": 8, "central_orchestration": 9,
}
LICENSE_STATES = ("none", "evaluating", "not_subscribed", "subscribed", "expired", "deactivated")

VPN_TABLE = f"{_SFOS}.6.1.1.1.1"  # sfosIPSecVpnTunnelTable entries
VPN_STATES = ("inactive", "active", "partially_active")
FAN_TABLE = f"{_SFOS}.9.3.1"
POE_TABLE = f"{_SFOS}.9.5.1"
IF_COLUMNS: dict[str, str] = {
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "type": "1.3.6.1.2.1.2.2.1.3",
    "admin": "1.3.6.1.2.1.2.2.1.7",
    "oper": "1.3.6.1.2.1.2.2.1.8",
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "speed_mbps": "1.3.6.1.2.1.31.1.1.1.15",
}


@dataclass
class SnmpData:
    """Live data from the SNMP agent."""

    system: dict[str, Any] = field(default_factory=dict)
    interfaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    services: dict[str, dict[str, Any]] = field(default_factory=dict)
    licenses: dict[str, dict[str, Any]] = field(default_factory=dict)
    vpn: dict[str, dict[str, Any]] = field(default_factory=dict)
    poe: dict[str, dict[str, Any]] = field(default_factory=dict)
    fans: dict[str, int] = field(default_factory=dict)


def _state(states: tuple[str, ...], code: Any) -> str | None:
    if isinstance(code, int) and 0 <= code < len(states):
        return states[code]
    return None


def _expiry(value: Any) -> date | None:
    """Licence expiry such as "Feb 19 2027"; other texts ("fail") give None."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value.strip(), "%b %d %Y").date()
    except ValueError:
        return None


def _tenths(value: Any) -> float | None:
    if not isinstance(value, int) or value <= 0:
        return None
    return round(value / 10, 1)


def _clean(value: Any) -> Any:
    """Placeholder texts such as "Not Available" count as no value."""
    if isinstance(value, str) and value.strip().lower() in ("", "not available", "n/a"):
        return None
    return value


class SnmpCoordinator(DataUpdateCoordinator[SnmpData]):
    """Polls the SNMP agent of one firewall."""

    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: SnmpClient) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN}_snmp",
            update_interval=SNMP_SCAN_INTERVAL,
        )
        self.client = client

    async def _column(self, oid: str) -> dict[str, Any]:
        rows = await self.client.walk(oid)
        prefix = oid + "."
        return {k[len(prefix) :]: v for k, v in rows.items() if k.startswith(prefix)}

    async def _async_update_data(self) -> SnmpData:
        try:
            lic_oids = [f"{_SFOS}.5.{i}.{c}.0" for i in LICENSES.values() for c in (1, 2)]
            raw = await self.client.get(
                list(SYSTEM_OIDS.values()) + list(SERVICES.values()) + lic_oids
            )
            vpn_rows = table(await self.client.walk(VPN_TABLE), VPN_TABLE)
            poe_rows = table(await self.client.walk(POE_TABLE), POE_TABLE)
            fan_rows = table(await self.client.walk(FAN_TABLE), FAN_TABLE)
            loads = await self._column(HR_PROCESSOR_LOAD)
            columns = {key: await self._column(oid) for key, oid in IF_COLUMNS.items()}
        except SnmpError as err:
            raise UpdateFailed(f"SNMP: {err}") from err

        values = {key: _clean(raw.get(oid)) for key, oid in SYSTEM_OIDS.items()}
        cpu = [v for v in loads.values() if isinstance(v, int)]
        system = {
            "name": values["name"],
            "model": values["model"],
            "firmware": values["firmware"],
            "serial": values["serial"],
            "webcat_version": values["webcat_version"],
            "ips_version": values["ips_version"],
            "uptime_seconds": values["uptime"] // 100 if isinstance(values["uptime"], int) else None,
            "disk_percent": values["disk_percent"],
            "memory_percent": values["memory_percent"],
            "swap_percent": values["swap_percent"],
            "disk_capacity_mb": values["disk_capacity"],
            "memory_capacity_mb": values["memory_capacity"],
            "swap_capacity_mb": values["swap_capacity"],
            "http_hits": values["http_hits"],
            "smtp_hits": values["smtp_hits"],
            "cpu_temperature": _tenths(values["cpu_temperature"]),
            "npu_temperature": _tenths(values["npu_temperature"]),
            "cpu_percent": round(sum(cpu) / len(cpu), 1) if cpu else None,
        }

        interfaces: dict[str, dict[str, Any]] = {}
        for index in columns["descr"].keys() | columns["name"].keys():
            name = columns["name"].get(index) or columns["descr"].get(index)
            if not name:
                continue
            interfaces[str(name)] = {
                "index": index,
                "descr": columns["descr"].get(index),
                "type": columns["type"].get(index),
                "admin_up": columns["admin"].get(index) == 1,
                "link_up": columns["oper"].get(index) == 1,
                "in_octets": columns["in_octets"].get(index),
                "out_octets": columns["out_octets"].get(index),
                "speed_mbps": columns["speed_mbps"].get(index),
            }
        services = {
            key: {"code": raw.get(oid), "state": _state(SERVICE_STATES, raw.get(oid))}
            for key, oid in SERVICES.items()
            if raw.get(oid) is not None
        }
        licenses: dict[str, dict[str, Any]] = {}
        for key, i in LICENSES.items():
            code = raw.get(f"{_SFOS}.5.{i}.1.0")
            if code is None:
                continue
            licenses[key] = {
                "code": code,
                "state": _state(LICENSE_STATES, code),
                "expires": _expiry(raw.get(f"{_SFOS}.5.{i}.2.0")),
            }
        vpn = {
            str(row[2]): {
                "status": _state(VPN_STATES, row.get(9)),
                "activated": row.get(10) == 1,
                "tunnels": row.get(8),
                "policy": row.get(4),
                "type": row.get(5),
                "interface": row.get(7),
            }
            for row in vpn_rows.values()
            if row.get(2)
        }
        poe = {
            str(row.get(2) or idx): {
                "enabled": row.get(3) == 1,
                "limit_w": row[4] / 1000 if isinstance(row.get(4), int) else None,
                "power_w": round(row[5] / 1000, 1) if isinstance(row.get(5), int) else None,
            }
            for idx, row in poe_rows.items()
        }
        fans = {idx: row[2] for idx, row in fan_rows.items() if isinstance(row.get(2), int)}
        return SnmpData(
            system=system, interfaces=interfaces, services=services,
            licenses=licenses, vpn=vpn, poe=poe, fans=fans,
        )
