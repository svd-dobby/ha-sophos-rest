"""Coordinator for live data over SNMP v2c (read-only)."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, SNMP_SCAN_INTERVAL
from .snmp import SnmpClient, SnmpError

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
    "npu_temperature": f"{_SFOS}.9.1.0",
    "cpu_temperature": f"{_SFOS}.9.2.0",
}
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
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
            raw = await self.client.get(list(SYSTEM_OIDS.values()))
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
        return SnmpData(system=system, interfaces=interfaces)
