"""Diagnostics (API key and MAC addresses are redacted)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_API_KEY
from homeassistant.core import HomeAssistant

from . import SophosConfigEntry

TO_REDACT = {CONF_API_KEY, "macAddress", "snmp_community", "serial"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: SophosConfigEntry
) -> dict[str, Any]:
    data = entry.runtime_data.data
    return async_redact_data(
        {
            "entry": dict(entry.data),
            "dhcp_servers": data.dhcp_servers,
            "dhcp_leases": data.dhcp_leases,
            "hostname": data.hostname,
            "firewall_rules": data.firewall_rules,
            "nat_rules": data.nat_rules,
            "interfaces": data.interfaces,
            "live_users": data.live_users,
            "certificates": {
                k: {**v, "not_after": str(v.get("not_after")), "not_before": str(v.get("not_before"))}
                for k, v in (data.certificates or {}).items()
            },
            "ips": data.ips,
            "spoof": data.spoof,
            "hotfix": data.hotfix,
            "unavailable": data.unavailable,
            "options": dict(entry.options),
            "snmp": (
                {
                    "system": snmp.data.system,
                    "interfaces": snmp.data.interfaces,
                    "services": snmp.data.services,
                    "licenses": {
                        k: {**v, "expires": str(v.get("expires"))}
                        for k, v in snmp.data.licenses.items()
                    },
                    "vpn": snmp.data.vpn,
                    "poe": snmp.data.poe,
                    "fans": snmp.data.fans,
                }
                if (snmp := entry.runtime_data.snmp) is not None and snmp.data
                else None
            ),
        }, TO_REDACT
    )
