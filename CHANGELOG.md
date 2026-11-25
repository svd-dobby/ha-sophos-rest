# Changelog

## 0.5.0 (25 November 2026)
- Entities are grouped into sub-devices under the main firewall device: DHCP, firewall rules, NAT rules, interfaces, security. The main device keeps the system values (CPU, memory, temperatures, firmware, logged-in users). Device names are translated (en, nl). Entity IDs do not change.
- Shorter entity names inside a group (for example the rule name only).

## 0.4.1 (25 November 2026)
- SNMP: placeholder texts such as "Not Available" (web category version on this firewall) are treated as no value.

## 0.4.0 (25 November 2026)
- Live data over SNMP v2c (read-only), configured in the integration options (community and port; empty community turns SNMP off). Own minimal SNMP client (`snmp.py`), no extra dependency.
- New sensors (SNMP): CPU, memory, swap and disk usage, CPU and NPU temperature, last boot, firmware, IPS signature and web category versions, bytes received and sent per interface.
- New binary sensors (SNMP): live link state per interface.
- Device info gets model, firmware and serial number from SNMP.

## 0.3.0 (25 November 2026)
- Paging for collections (`pageSize=100`, `page=N`); the default page size of the API is 50.
- HTTP 403 no longer triggers re-authentication: a part the API profile cannot read is simply left out (listed under `unavailable` in diagnostics).
- Device name taken from the firewall hostname (`/administration/system-settings`).
- New binary sensors (read-only): one per firewall rule and per NAT rule (on = enabled), one per interface (on = enabled; the API has no live link state), intrusion prevention, spoof protection, automatic hotfixes.
- New sensors: logged-in users (list as attribute, not recorded), days until expiry per certificate (parsed from the certificate; the certificate itself is not kept).

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
