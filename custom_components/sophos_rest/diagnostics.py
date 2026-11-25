"""Diagnostiek (API-sleutel en MAC-adressen worden weggelaten)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_API_KEY
from homeassistant.core import HomeAssistant

from . import SophosConfigEntry

TO_REDACT = {CONF_API_KEY, "macAddress"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: SophosConfigEntry
) -> dict[str, Any]:
    data = entry.runtime_data.data
    return async_redact_data(
        {
            "entry": dict(entry.data),
            "dhcp_servers": data.dhcp_servers,
            "dhcp_leases": data.dhcp_leases,
        }, TO_REDACT
    )
