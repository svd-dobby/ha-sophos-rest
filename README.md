# Sophos Firewall (REST) for Home Assistant

Custom integration `sophos_rest` for the REST API of Sophos Firewall (SFOS v23 and later).

## Status

Version 0.2.0, read-only:

- Per DHCPv4 server: number of static reservations (attributes: enabled, interface, pools, list of reservations) and free addresses in the dynamic pools.
- Active DHCP leases (static and dynamic, list as attribute).
- Dynamic DHCP leases: devices without a static reservation.

Entity names follow the Home Assistant language (English and Dutch included).

## Installation (manual)

1. Copy `custom_components/sophos_rest` to `/config/custom_components/`.
2. Restart Home Assistant.
3. Settings > Devices & services > Add integration > "Sophos Firewall (REST)".
4. Enter a name, host, port (default 4444) and the API key (Administration > API access on the firewall).

The script `tools/sophos_rest_sync.py` installs and updates the integration straight from this private repo, using a read-only deploy key.

See `LOG.md` for the development log and `CHANGELOG.md` for the versions.
