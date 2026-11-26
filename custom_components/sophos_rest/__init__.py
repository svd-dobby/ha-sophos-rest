"""Sophos Firewall via the REST API (SFOS v23+)."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_API_KEY, CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.typing import ConfigType
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
from .entity import GROUPS, group_identifier, main_device_info
from .snmp import SnmpClient
from .services import async_setup_services
from .snmp_coordinator import SnmpCoordinator

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]

type SophosConfigEntry = ConfigEntry[SophosCoordinator]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the actions once for the integration."""
    async_setup_services(hass)
    return True


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

    # Main device first, so the sub-devices (DHCP, rules, ...) can refer to it.
    snmp_data = coordinator.snmp.data if coordinator.snmp is not None else None
    registry = dr.async_get(hass)
    main = registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        **main_device_info(entry, coordinator.data.hostname, snmp_data.system if snmp_data else {}),
    )
    for group in GROUPS:
        registry.async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={(DOMAIN, group_identifier(entry, group))},
            manufacturer="Sophos",
            model="Sophos Firewall",
            translation_key=group,
            translation_placeholders={"host": coordinator.data.hostname or entry.title},
            via_device_id=main.id,
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
