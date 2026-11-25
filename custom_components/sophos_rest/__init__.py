"""Sophos Firewall via de REST-API (SFOS v23+)."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_API_KEY, CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import SophosRestClient
from .const import CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL
from .coordinator import SophosCoordinator

PLATFORMS: list[Platform] = [Platform.SENSOR]

type SophosConfigEntry = ConfigEntry[SophosCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Koppeling opzetten."""
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
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Koppeling ontladen."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
