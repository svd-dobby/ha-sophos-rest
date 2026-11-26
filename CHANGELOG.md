# Changelog

## 0.12.0 (26 November 2026)
- New sensor "IPsec live connections" (VPN device): number of live site-to-site connections, with bytes and packets sent and received per connection as attribute (not recorded).
- New sensor "DoS traffic dropped" (security device): traffic dropped by DoS protection, summed over SYN, UDP, TCP, ICMP and IP floods; per type as attributes.
- New sensor "Security updates" (security device): number of security hotfixes applied, with CVE, severity, applied time and advisory as attributes.
- Each part is optional like the others (left out when the API profile cannot read it).

## 0.11.0 (26 November 2026)
- New SNMP sensors: web requests (HTTP proxy hits) and SMTP requests, counters since boot (total increasing).
- The sensors for disk, memory and swap use get the capacity in MB as attribute `capacity_mb`.
- Checked against the official SOPHOS-XG-MIB; see ROADMAP.md.

## 0.10.1 (26 November 2026)
- SNMP traps from Sophos: the alert text is split into `alert_id` and `alert_text`; `message` now holds only the alert text. Sophos sends every alert with the same trap OID (`1.3.6.1.4.1.2604.5.1.8.1.1`), so the text is what tells alerts apart.
- The fixed device info Sophos adds to every trap (hostname, model, firmware, serial number, date) is left out of the event and the sensor; the serial number stays private.

## 0.10.0 (26 November 2026)
- SNMP trap receiver (v1 and v2c), off by default; turned on in the options (uses the SNMP community, UDP port 162 by default). Only traps from the firewall's address with the right community are accepted.
- Every trap fires the event `sophos_rest_trap` (trap OID, name for standard traps, version, readable message, varbinds, uptime), usable as an automation trigger.
- New sensor "Last SNMP trap" (timestamp) with the last trap and counters as attributes (not recorded). Diagnostics list the last 20 traps.
- A port that cannot be opened is logged and shown on the sensor; the rest of the integration keeps working.

## 0.9.0 (26 November 2026)
- New action `sophos_rest.set_dhcp_lease_time`: sets the default and maximum lease time (minutes) of a DHCP server (only on servers allowed in the options). Writes only `defaultLifetime` and `maxLifetime`, reads back and verifies. `dry_run` shows the current values. Meant for a short lease time while addresses move; devices pick it up at their next renewal.

## 0.8.0 (26 November 2026)
- New action `sophos_rest.set_dhcp_pools`: replaces the dynamic pools of a DHCP server (only on servers allowed in the options). Checks: valid ranges, no overlap between pools, no reservation inside a pool. The response lists the dynamic leases that fall outside the new pools. Writes only `addressPools`, reads back and verifies. `dry_run` supported.

## 0.7.0 (26 November 2026)
- First write features: actions `sophos_rest.add_dhcp_reservation` and `sophos_rest.remove_dhcp_reservation`.
  - Only on DHCP servers selected in the integration options (none by default).
  - Checks before writing: valid name, MAC and IPv4; IP outside the dynamic pools; no duplicate MAC or IP; removal needs exactly one match.
  - `dry_run` only checks and reports.
  - Writes only `clientReservations` (PATCH), reads the server back and verifies that the reservations are as expected and that nothing else changed; the result is returned as action response.
  - Clear messages for a missing write permission (Network), a refusal by the firewall and a possible change after a timeout.
- Options flow: SNMP and the writable DHCP servers in one form.

## 0.6.3 (26 November 2026)
- DHCP is optional like every other part. DHCP falls under the "Network" permission of the API profile; without it only the DHCP (and other network) entities are left out. Setup succeeds as soon as the key is valid (HTTP 403 means a valid key without permission for that part); only HTTP 401 asks for a new key.
- The lease sensors and the logged-in users sensor are created as soon as the part can be read, also when a permission is added later (no restart needed).
- Free addresses are unavailable when the leases cannot be read.

## 0.6.2 (25 November 2026)
- Licence sensors show the expiry date (device class date) instead of days; status, days remaining and `perpetual` are attributes. A perpetual licence shows 31 December 2999.

## 0.6.1 (25 November 2026)
- A licence that Sophos reports as valid until Dec 31 2999 is treated as perpetual: no day count, attribute `perpetual`, disabled by default for new installations.

## 0.6.0 (25 November 2026)
- Reading completed over SNMP, in three new sub-devices:
  - Services: one binary sensor per firewall service (on = running); services that were never started are disabled by default.
  - Licences: days until expiry per subscription, status as attribute; inactive subscriptions are disabled by default.
  - VPN: one connectivity binary sensor per IPsec connection (status, activation, policy and interface as attributes).
- PoE power per port (interfaces sub-device) and fan speed (main device).

## 0.5.2 (25 November 2026)
- DHCP entity names without the word "DHCP"; the sub-device already says it.

## 0.5.1 (25 November 2026)
- Sub-devices are created in setup with `via_device_id` (the `via_device` key in DeviceInfo is deprecated since HA 2026 and stops working in 2027.8).

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
