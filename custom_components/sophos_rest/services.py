"""Actions that write to the firewall. Every write is checked before and after."""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address
import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv

from .api import SophosApiError, SophosError, SophosForbiddenError
from .const import CONF_DHCP_WRITE_SERVERS, DOMAIN
from .coordinator import SophosCoordinator

_LOGGER = logging.getLogger(__name__)

ATTR_CONFIG_ENTRY = "config_entry_id"
ATTR_SERVER = "server"
ATTR_NAME = "name"
ATTR_MAC = "mac"
ATTR_IP = "ip"
ATTR_DRY_RUN = "dry_run"

SERVICE_ADD_RESERVATION = "add_dhcp_reservation"
SERVICE_REMOVE_RESERVATION = "remove_dhcp_reservation"
SERVICE_SET_POOLS = "set_dhcp_pools"
SERVICE_SET_LEASE_TIME = "set_dhcp_lease_time"
ATTR_POOLS = "pools"
ATTR_DEFAULT_LEASE = "default_lease_time"
ATTR_MAX_LEASE = "max_lease_time"

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,50}$")

# Fields that are expected to change on a write; everything else must stay equal.
_VOLATILE_RES = ("clientReservations", "updatedAt", "createdAt")
_VOLATILE_POOLS = ("addressPools", "updatedAt", "createdAt")
_VOLATILE_LEASE = ("defaultLifetime", "maxLifetime", "updatedAt", "createdAt")

_BASE_SCHEMA = {
    vol.Optional(ATTR_CONFIG_ENTRY): cv.string,
    vol.Required(ATTR_SERVER): cv.string,
    vol.Optional(ATTR_DRY_RUN, default=False): cv.boolean,
}
ADD_SCHEMA = vol.Schema(
    {
        **_BASE_SCHEMA,
        vol.Required(ATTR_NAME): cv.string,
        vol.Required(ATTR_MAC): cv.string,
        vol.Required(ATTR_IP): cv.string,
    }
)
POOLS_SCHEMA = vol.Schema(
    {
        **_BASE_SCHEMA,
        vol.Required(ATTR_POOLS): vol.All(cv.ensure_list, [cv.string], vol.Length(min=1, max=16)),
    }
)
LEASE_SCHEMA = vol.Schema(
    {
        **_BASE_SCHEMA,
        # Minutes, as in the Sophos web console.
        vol.Required(ATTR_DEFAULT_LEASE): vol.All(vol.Coerce(int), vol.Range(min=1, max=43200)),
        vol.Required(ATTR_MAX_LEASE): vol.All(vol.Coerce(int), vol.Range(min=1, max=43200)),
    }
)
REMOVE_SCHEMA = vol.Schema(
    {
        **_BASE_SCHEMA,
        vol.Optional(ATTR_MAC): cv.string,
        vol.Optional(ATTR_IP): cv.string,
    }
)


def _err(key: str, **placeholders: Any) -> ServiceValidationError:
    return ServiceValidationError(
        translation_domain=DOMAIN,
        translation_key=key,
        translation_placeholders={k: str(v) for k, v in placeholders.items()},
    )


def _norm_mac(mac: str) -> str:
    if not _MAC_RE.match(mac.strip()):
        raise _err("invalid_mac", mac=mac)
    return mac.strip().replace("-", ":").upper()


def _norm_ip(ip: str) -> IPv4Address:
    try:
        addr = ip_address(ip.strip())
    except ValueError as err:
        raise _err("invalid_ip", ip=ip) from err
    if not isinstance(addr, IPv4Address):
        raise _err("invalid_ip", ip=ip)
    return addr


def _pools(server: dict[str, Any]) -> list[tuple[IPv4Address, IPv4Address]]:
    pools = []
    for p in server.get("addressPools") or []:
        try:
            pools.append((ip_address(p["startAddressIpv4"]), ip_address(p["endAddressIpv4"])))
        except (KeyError, ValueError):
            continue
    return pools


def _core(server: dict[str, Any], volatile: tuple[str, ...] = _VOLATILE_RES) -> dict[str, Any]:
    return {k: v for k, v in server.items() if k not in volatile}


def _res_set(reservations: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {
        ((r.get("macAddress") or "").upper(), r.get("ipv4Address") or "") for r in reservations
    }


def _coordinator(hass: HomeAssistant, call: ServiceCall) -> SophosCoordinator:
    entries = [
        e for e in hass.config_entries.async_entries(DOMAIN)
        if e.state is ConfigEntryState.LOADED
    ]
    wanted = call.data.get(ATTR_CONFIG_ENTRY)
    if wanted:
        entries = [e for e in entries if e.entry_id == wanted]
    if len(entries) != 1:
        raise _err("entry_not_found" if wanted or not entries else "entry_ambiguous")
    return entries[0].runtime_data


async def _read_server(coordinator: SophosCoordinator, name: str) -> dict[str, Any]:
    try:
        servers = await coordinator.client.get_dhcp_servers_v4()
    except SophosForbiddenError as err:
        raise _err("no_read_permission") from err
    except SophosError as err:
        raise HomeAssistantError(f"Sophos: {err}") from err
    for s in servers:
        if s.get("name") == name:
            return s
    raise _err("server_not_found", server=name, servers=", ".join(s.get("name", "") for s in servers))


async def _write(
    coordinator: SophosCoordinator,
    name: str,
    before: dict[str, Any],
    new_list: list[dict[str, Any]],
    action: str,
) -> dict[str, Any]:
    """PATCH only clientReservations, then read back and verify."""
    try:
        await coordinator.client.patch_dhcp_server_v4(name, {"clientReservations": new_list})
    except SophosForbiddenError as err:
        raise _err("no_write_permission") from err
    except SophosApiError as err:
        raise _err("firewall_refused", status=err.status, detail=err.body[:300]) from err
    except SophosError as err:
        # A timeout does not prove that nothing changed: the refresh below shows the real state.
        await coordinator.async_request_refresh()
        raise HomeAssistantError(
            f"Sophos: {err}. The change may have been applied; check the reservations sensor."
        ) from err

    after = await _read_server(coordinator, name)
    expected = _res_set(new_list)
    got = _res_set(after.get("clientReservations") or [])
    unchanged = _core(after) == _core(before)
    await coordinator.async_request_refresh()
    result = {
        "action": action,
        "server": name,
        "reservations_before": len(before.get("clientReservations") or []),
        "reservations_after": len(after.get("clientReservations") or []),
        "as_expected": got == expected,
        "rest_of_server_unchanged": unchanged,
        "dry_run": False,
    }
    _LOGGER.info("DHCP %s on %s: %s", action, name, result)
    if got != expected or not unchanged:
        raise HomeAssistantError(
            f"Sophos: the firewall accepted the change but the read-back differs: {result}"
        )
    return result


def _check_allowed(coordinator: SophosCoordinator, server: str) -> None:
    allowed = coordinator.config_entry.options.get(CONF_DHCP_WRITE_SERVERS) or []
    if server not in allowed:
        raise _err("write_not_allowed", server=server)


async def _add(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    coordinator = _coordinator(hass, call)
    server = call.data[ATTR_SERVER]
    _check_allowed(coordinator, server)
    name = call.data[ATTR_NAME].strip()
    if not _NAME_RE.match(name):
        raise _err("invalid_name", name=name)
    mac = _norm_mac(call.data[ATTR_MAC])
    ip = _norm_ip(call.data[ATTR_IP])

    before = await _read_server(coordinator, server)
    current = list(before.get("clientReservations") or [])
    for lo, hi in _pools(before):
        if lo <= ip <= hi:
            raise _err("ip_in_pool", ip=ip, start=lo, end=hi)
    for r in current:
        if (r.get("macAddress") or "").upper() == mac:
            raise _err("mac_exists", mac=mac, ip=r.get("ipv4Address"), name=r.get("hostname"))
        if r.get("ipv4Address") == str(ip):
            raise _err("ip_exists", ip=ip, mac=r.get("macAddress"), name=r.get("hostname"))
    new_list = [*current, {"hostname": name, "macAddress": mac, "ipv4Address": str(ip)}]

    if call.data[ATTR_DRY_RUN]:
        return {
            "action": "add",
            "server": server,
            "reservations_before": len(current),
            "reservations_after": len(new_list),
            "dry_run": True,
        }
    return await _write(coordinator, server, before, new_list, "add")


async def _remove(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    coordinator = _coordinator(hass, call)
    server = call.data[ATTR_SERVER]
    _check_allowed(coordinator, server)
    mac = _norm_mac(call.data[ATTR_MAC]) if call.data.get(ATTR_MAC) else None
    ip = str(_norm_ip(call.data[ATTR_IP])) if call.data.get(ATTR_IP) else None
    if mac is None and ip is None:
        raise _err("mac_or_ip_required")

    before = await _read_server(coordinator, server)
    current = list(before.get("clientReservations") or [])

    def matches(r: dict[str, Any]) -> bool:
        return (mac is None or (r.get("macAddress") or "").upper() == mac) and (
            ip is None or r.get("ipv4Address") == ip
        )

    hits = [r for r in current if matches(r)]
    if len(hits) != 1:
        raise _err("reservation_not_unique", count=len(hits))
    new_list = [r for r in current if not matches(r)]

    if call.data[ATTR_DRY_RUN]:
        hit = hits[0]
        return {
            "action": "remove",
            "server": server,
            "reservation": {
                "name": hit.get("hostname"), "mac": hit.get("macAddress"), "ip": hit.get("ipv4Address"),
            },
            "reservations_before": len(current),
            "reservations_after": len(new_list),
            "dry_run": True,
        }
    return await _write(coordinator, server, before, new_list, "remove")


def _parse_pools(raw: list[str]) -> list[tuple[IPv4Address, IPv4Address]]:
    pools = []
    for item in raw:
        start, sep, end = item.replace(" ", "").partition("-")
        if not sep:
            raise _err("invalid_pool", pool=item)
        lo, hi = _norm_ip(start), _norm_ip(end)
        if lo > hi:
            raise _err("invalid_pool", pool=item)
        pools.append((lo, hi))
    pools.sort()
    for (a_lo, a_hi), (b_lo, b_hi) in zip(pools, pools[1:]):
        if b_lo <= a_hi:
            raise _err("pools_overlap", a=f"{a_lo}-{a_hi}", b=f"{b_lo}-{b_hi}")
    return pools


async def _set_pools(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    coordinator = _coordinator(hass, call)
    server = call.data[ATTR_SERVER]
    _check_allowed(coordinator, server)
    pools = _parse_pools(call.data[ATTR_POOLS])

    before = await _read_server(coordinator, server)
    for r in before.get("clientReservations") or []:
        try:
            rip = ip_address(r.get("ipv4Address") or "")
        except ValueError:
            continue
        for lo, hi in pools:
            if lo <= rip <= hi:
                raise _err(
                    "reservation_in_pool", ip=rip, name=r.get("hostname"), start=lo, end=hi
                )
    new_pools = [{"startAddressIpv4": str(lo), "endAddressIpv4": str(hi)} for lo, hi in pools]

    # Devices with a dynamic lease that falls outside the new pools: they keep their
    # address until the lease is renewed and then get a new one.
    old = _pools(before)
    moved = []
    for lease in coordinator.data.dhcp_leases or []:
        if lease.get("leaseType") != "dynamic":
            continue
        try:
            lip = ip_address(lease.get("leasedIp") or "")
        except ValueError:
            continue
        in_old = any(lo <= lip <= hi for lo, hi in old)
        in_new = any(lo <= lip <= hi for lo, hi in pools)
        if in_old and not in_new:
            moved.append({"ip": str(lip), "mac": lease.get("macAddress"), "hostname": lease.get("clientHostName")})

    summary = {
        "action": "set_pools",
        "server": server,
        "pools_before": [f"{lo}-{hi}" for lo, hi in old],
        "pools_after": [f"{lo}-{hi}" for lo, hi in pools],
        "addresses_before": sum(int(hi) - int(lo) + 1 for lo, hi in old),
        "addresses_after": sum(int(hi) - int(lo) + 1 for lo, hi in pools),
        "dynamic_leases_outside_new_pools": moved,
    }
    if call.data[ATTR_DRY_RUN]:
        return {**summary, "dry_run": True}

    try:
        await coordinator.client.patch_dhcp_server_v4(server, {"addressPools": new_pools})
    except SophosForbiddenError as err:
        raise _err("no_write_permission") from err
    except SophosApiError as err:
        raise _err("firewall_refused", status=err.status, detail=err.body[:300]) from err
    except SophosError as err:
        await coordinator.async_request_refresh()
        raise HomeAssistantError(
            f"Sophos: {err}. The change may have been applied; check the reservations sensor."
        ) from err

    after = await _read_server(coordinator, server)
    got = sorted((p.get("startAddressIpv4"), p.get("endAddressIpv4")) for p in after.get("addressPools") or [])
    want = sorted((p["startAddressIpv4"], p["endAddressIpv4"]) for p in new_pools)
    unchanged = _core(after, _VOLATILE_POOLS) == _core(before, _VOLATILE_POOLS)
    await coordinator.async_request_refresh()
    result = {**summary, "as_expected": got == want, "rest_of_server_unchanged": unchanged, "dry_run": False}
    _LOGGER.info("DHCP set_pools on %s: %s", server, result)
    if got != want or not unchanged:
        raise HomeAssistantError(
            f"Sophos: the firewall accepted the change but the read-back differs: {result}"
        )
    return result


async def _set_lease_time(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    coordinator = _coordinator(hass, call)
    server = call.data[ATTR_SERVER]
    _check_allowed(coordinator, server)
    default, maximum = call.data[ATTR_DEFAULT_LEASE], call.data[ATTR_MAX_LEASE]
    if maximum < default:
        raise _err("lease_max_below_default", default=default, maximum=maximum)

    before = await _read_server(coordinator, server)
    summary = {
        "action": "set_lease_time",
        "server": server,
        "default_lease_time_before": before.get("defaultLifetime"),
        "max_lease_time_before": before.get("maxLifetime"),
        "default_lease_time_after": default,
        "max_lease_time_after": maximum,
        "unit": "minutes",
    }
    if call.data[ATTR_DRY_RUN]:
        return {**summary, "dry_run": True}

    try:
        await coordinator.client.patch_dhcp_server_v4(
            server, {"defaultLifetime": default, "maxLifetime": maximum}
        )
    except SophosForbiddenError as err:
        raise _err("no_write_permission") from err
    except SophosApiError as err:
        raise _err("firewall_refused", status=err.status, detail=err.body[:300]) from err
    except SophosError as err:
        await coordinator.async_request_refresh()
        raise HomeAssistantError(
            f"Sophos: {err}. The change may have been applied; read the server back."
        ) from err

    after = await _read_server(coordinator, server)
    got = (int(after.get("defaultLifetime") or 0), int(after.get("maxLifetime") or 0))
    unchanged = _core(after, _VOLATILE_LEASE) == _core(before, _VOLATILE_LEASE)
    await coordinator.async_request_refresh()
    result = {
        **summary,
        "as_expected": got == (default, maximum),
        "rest_of_server_unchanged": unchanged,
        "dry_run": False,
    }
    _LOGGER.info("DHCP set_lease_time on %s: %s", server, result)
    if got != (default, maximum) or not unchanged:
        raise HomeAssistantError(
            f"Sophos: the firewall accepted the change but the read-back differs: {result}"
        )
    return result


def async_setup_services(hass: HomeAssistant) -> None:
    """Register the actions (once for the domain)."""
    if hass.services.has_service(DOMAIN, SERVICE_SET_LEASE_TIME):
        return

    async def add(call: ServiceCall) -> ServiceResponse:
        return await _add(hass, call)

    async def remove(call: ServiceCall) -> ServiceResponse:
        return await _remove(hass, call)

    hass.services.async_register(
        DOMAIN, SERVICE_ADD_RESERVATION, add, schema=ADD_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )
    hass.services.async_register(
        DOMAIN, SERVICE_REMOVE_RESERVATION, remove, schema=REMOVE_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )

    async def set_pools(call: ServiceCall) -> ServiceResponse:
        return await _set_pools(hass, call)

    hass.services.async_register(
        DOMAIN, SERVICE_SET_POOLS, set_pools, schema=POOLS_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )

    async def set_lease_time(call: ServiceCall) -> ServiceResponse:
        return await _set_lease_time(hass, call)

    hass.services.async_register(
        DOMAIN, SERVICE_SET_LEASE_TIME, set_lease_time, schema=LEASE_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )
