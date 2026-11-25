"""Sophos Firewall via the REST API (SFOS v23+)."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_API_KEY, CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import SophosRestClient
from .const import (
    CONF_SNMP_COMMUNITY,
    CONF_SNMP_PORT,
    CONF_VERIFY_SSL,
    DEFAULT_SNMP_PORT,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)
from .coordinator import SophosCoordinator
from .snmp import SnmpClient
from .snmp_coordinator import SnmpCoordinator

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]

type SophosConfigEntry = ConfigEntry[SophosCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Set up a config entry."""
    verify_ssl = entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
    client = SophosRestClient(
        async_get_clientsession(hass, verify_ssl=verify_ssl),
        entry.data[CONF_HOST],
        entry.data[CONF_PORT],
        entry.data[CONF_API_KEY],
        verify_ssl,
    )
    coordinator = SophosCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()

    coordinator.snmp = None
    if community := entry.options.get(CONF_SNMP_COMMUNITY):
        snmp = SnmpCoordinator(
            hass,
            entry,
            SnmpClient(
                entry.data[CONF_HOST],
                community,
                entry.options.get(CONF_SNMP_PORT, DEFAULT_SNMP_PORT),
            ),
        )
        # SNMP is optional: a failure here must not block the REST part.
        await snmp.async_refresh()
        coordinator.snmp = snmp
        system = snmp.data.system if snmp.data else {}
        if system:
            dr.async_get(hass).async_get_or_create(
                config_entry_id=entry.entry_id,
                identifiers={(DOMAIN, entry.unique_id or entry.entry_id)},
                model=system.get("model"),
                sw_version=system.get("firmware"),
                serial_number=system.get("serial"),
            )

    entry.runtime_data = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_options_updated(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Reload when the options (SNMP) change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
