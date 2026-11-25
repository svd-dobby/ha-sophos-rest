"""Config flow: name, host, port and API key."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_API_KEY, CONF_HOST, CONF_NAME, CONF_PORT
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    SophosAuthError,
    SophosConnectionError,
    SophosError,
    SophosForbiddenError,
    SophosRestClient,
)
from .const import CONF_VERIFY_SSL, DEFAULT_NAME, DEFAULT_PORT, DEFAULT_VERIFY_SSL, DOMAIN


class SophosRestConfigFlow(ConfigFlow, domain=DOMAIN):
    """UI config flow."""

    VERSION = 1

    async def _test(self, data: dict[str, Any]) -> str | None:
        client = SophosRestClient(
            async_get_clientsession(self.hass, verify_ssl=data[CONF_VERIFY_SSL]),
            data[CONF_HOST],
            data[CONF_PORT],
            data[CONF_API_KEY],
            data[CONF_VERIFY_SSL],
        )
        try:
            await client.get_dhcp_servers_v4()
        except (SophosAuthError, SophosForbiddenError):
            return "invalid_auth"
        except SophosConnectionError:
            return "cannot_connect"
        except SophosError:
            return "unknown"
        return None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(
                f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}"
            )
            self._abort_if_unique_id_configured()
            if (err := await self._test(user_input)) is None:
                data = {k: v for k, v in user_input.items() if k != CONF_NAME}
                return self.async_create_entry(
                    title=user_input.get(CONF_NAME) or DEFAULT_NAME, data=data
                )
            errors["base"] = err
        schema = vol.Schema(
            {
                vol.Required(CONF_NAME, default=DEFAULT_NAME): str,
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
                vol.Required(CONF_API_KEY): str,
                vol.Required(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(schema, user_input),
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if user_input is not None:
            data = {**entry.data, CONF_API_KEY: user_input[CONF_API_KEY]}
            if (err := await self._test(data)) is None:
                return self.async_update_reload_and_abort(entry, data=data)
            errors["base"] = err
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_API_KEY): str}),
            errors=errors,
        )
