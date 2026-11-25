# Changelog

## 0.2.1 (25 November 2026)
- Everything in the repository is now in English (code, README, changelog, log). The Home Assistant UI follows the user's language (English and Dutch).
- `tools/sophos_rest_sync.py`: English output, action `key` (old name `sleutel` still accepted), updates itself on `pull`.

## 0.2.0 (25 November 2026)
- Active DHCP leases via `GET /network/dhcp/server/leases/ipv4` (follows `pages.nextKey` when the firewall returns one).
- New sensors: active DHCP leases (static and dynamic, list as attribute), dynamic DHCP leases (devices without a static reservation), free addresses in the dynamic pools per server.
- The reservations sensor now lists the reservations (hostname, MAC, IP) as an attribute. Large lists are excluded from the recorder.
- The config flow asks for a name (default "Sophos Firewall") for new entries.
- Diagnostics include the leases (MAC redacted).
- `tools/sophos_rest_sync.py`: installs the integration from this repo on HA (read-only deploy key).

## 0.1.0 (25 November 2026)
- First version: config flow with re-authentication, coordinator (60 s), sensor per DHCPv4 server with the number of reservations, diagnostics without API key and MAC addresses.
