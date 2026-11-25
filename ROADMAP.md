# Roadmap: API functions per category and priority

Draft of 25 November 2026, updated after version 0.6.0. Reading always comes first.

Operations: **R** = read (GET), **C** = create (POST), **U** = update (PUT/PATCH), **D** = delete (DELETE).
The operations listed are what the resource type normally offers (collection: R C U D, settings object: R U). They have not all been verified yet: the documentation pages are partly unreachable, and `GET /network/interfaces/network-interfaces` is documented as read-only. Each category is checked against the firewall (read-only GET) before it is built.

Priority for Home Assistant: **1** = high value, build first; **2** = useful; **3** = nice to have; **4** = not planned (security-sensitive or no value in HA).

| # | Category | API resources | Ops | Prio read | Prio write | In Home Assistant |
|---|---|---|---|---|---|---|
| 1 | DHCP | DHCPv4/v6 servers, leases, relays | R C U D | 1 (done) | 1: reservations (C, D) | sensors (done); actions add/remove reservation |
| 2 | Gateways / WAN | routing gateways | R U | 1 (no live state in REST; WAN link via SNMP, done) | 4 | link of the WAN port (interfaces sub-device) |
| 3 | Interfaces | network interfaces (REST), IF-MIB (SNMP), PoE | R | 1 (done) | 4 | sub-device interfaces: enabled, link, received/sent, PoE power |
| 4 | Firewall rules | firewall rules, NAT rules, ACL exceptions | R C U D | 1 (done) | 1: enable/disable (U) | sub-devices firewall rules and NAT rules; later a switch per rule |
| 5 | Address objects | IPv4/IPv6/MAC/FQDN hosts and groups, country groups | R C U D | 2 | 2: add/remove a host to/from a group | actions; together with firewall rules |
| 6 | DNS | DNS host entries, request routes, DNS settings | R C U D | 2 | 2: host entries (C, D) | actions: local DNS name for a device |
| 7 | System | firmware, uptime, CPU, memory, disk, temperatures, fans (SNMP); hotfix, pattern updates, backup (REST) | R U | 2 (done except backup and update availability) | 4 | main device |
| 8 | Certificates | certificates, CAs, CSRs, CRLs | R C D | 2 (done) | 4 | sub-device security: days until expiry |
| 9 | VPN status | IPsec connections (SNMP), SSL VPN settings (REST) | R C U D | 3 (done for IPsec) | 3: connect/disconnect tunnel | sub-device VPN: one binary sensor per connection |
| 10 | Live users | authentication live users, user login/logout | R + action | 3 (done) | 3 | main device: logged-in users |
| 11 | Web and application filter | web filter policies, exceptions, URL groups, application filter | R C U D | 3 | 3: toggle exception or URL group entry | switch or action |
| 12 | Protection status | IPS, spoof protection, hotfixes (REST); service states and licences (SNMP) | R U | 3 (done) | 4 | sub-devices security, services, licences |
| 13 | Traffic shaping | policies, settings | R C U D | 3 | 3 | select or switch per policy |
| 14 | Wireless hotspots | hotspots, vouchers, settings | R C D | 3 | 3: create a guest voucher | button or action |
| 15 | Logging and monitoring | syslog servers, log settings, SNMP, NetFlow, notification list | R U | 3 | 4 | diagnostics only |
| 16 | Routing (other) | unicast/multicast routes, SD-WAN routes, neighbors, router advertisements | R C U D | 3 | 4 | diagnostics only |
| 17 | Administration | access profiles, API access, portal, schedules, messages, system settings | R U | 3 | 4 (never) | read-only diagnostics at most |
| 18 | Authentication | users, groups, servers, TOTP, STAS, SSO, password settings | R C U D | 4 | 4 (never) | not planned |
| 19 | Other | SSL/TLS inspection, WAF, spoof protection, support access, cellular WAN, mDNS | R C U D | 4 | 4 | not planned |

## SNMP (read-only, live data)

Own SNMP v2c client, community in the integration options. Verified on the firewall (SOPHOS-XG-MIB base `1.3.6.1.4.1.2604.5.1`):

| Data | OID | Used in |
|---|---|---|
| Name, model, firmware, serial, web category and IPS versions | `.1.1.0` to `.1.6.0` | device info, main device |
| Uptime (TimeTicks), disk, memory, swap | `.2.2.0`, `.2.4.2.0`, `.2.5.2.0`, `.2.5.4.0` | main device |
| Service states (21 services) | `.3.1.0` to `.3.21.0` | sub-device services |
| HA cluster status | `.4.x` | not used (cluster disabled) |
| Licences (status, expiry) | `.5.1.x` to `.5.9.x` | sub-device licences |
| IPsec connections | `.6.1.1.1` | sub-device VPN |
| NPU and CPU temperature, fans, PoE | `.9.1.0`, `.9.2.0`, `.9.3`, `.9.5` | main device, sub-device interfaces |
| CPU load per core | HOST-RESOURCES-MIB `1.3.6.1.2.1.25.3.3.1.2` | main device |
| Interfaces (name, type, admin and link state, 64-bit counters, speed) | IF-MIB `1.3.6.1.2.1.2.2` and `1.3.6.1.2.1.31.1.1` | sub-device interfaces |

Not used yet: HTTP/FTP/mail hit counters (`.2.7.0` to `.2.9.x`), wireless access points (`.7.1`).

## Verified read endpoints (25 November 2026, profile HA-API with read access on everything)

Checked with read-only GET requests from HA-test. Paging on collections: `?pageSize=100&page=N` (default page size 50, maximum 100); the response has `pages` with `current`, `size`, `maxSize`. The leases list uses a different paging object (`fromKey`, `size`, `maxSize`).

| Category | Path | Items now | Remarks |
|---|---|---|---|
| DHCP | `/network/dhcp/server/servers/ipv4` | 2 | in use (0.2.x) |
| DHCP | `/network/dhcp/server/leases/ipv4` | 59 | in use (0.2.x) |
| DHCP | `/network/dhcp/server/servers/ipv6`, `/network/dhcp/relays/ipv4` | 0 | |
| Gateways | `/routing/gateways/ipv4` | 1 | configuration only (name, interface, IP, type), **no live up/down status** |
| Interfaces | `/network/interfaces/network-interfaces` | 9 | fields still to be checked for link status |
| Zones | `/network/zones` | 6 | |
| Firewall rules | `/firewall/rules/ipv4` | 14 | |
| NAT rules | `/nat/rules/ipv4` | 16 | has `enabled` |
| Address objects | `/network/addresses/ipv4` (52, two pages), `/ipv6`, `/mac` (28), `/fqdn` (50+) | | |
| Address groups | `/network/address-groups/ipv4`, `/ipv6`, `/fqdn`, `/country` | | |
| DNS | `/network/dns/host-entries` (3), `/network/dns/request-routes`, `/network/dns/settings` | | |
| Services | `/network/services` (50+), `/network/service-groups` | | |
| System | `/system/security-updates`, `/system/hotfix/settings`, `/system/pattern-updates/settings`, `/system/backup/settings` | | no firmware version or "update available" field seen yet |
| Certificates | `/certificate/certificates` (2), `/certificate/certificate-authorities` (50+) | | expiry date to be extracted from the certificate |
| Live users | `/authentication/live-users` | 4 | |
| Users and groups | `/authentication/users`, `/authentication/user-groups` | | sensitive, not exposed in HA |
| Administration | `/administration/system-settings` (hostname RedDwarf), `/administration/schedules` | | |
| Protection | `/intrusion-prevention/settings`, `/intrusion-prevention/policies`, `/malware-protection/settings`, `/zero-day-protection/settings`, `/spoof-protection/settings` | | |
| Web filter | `/web/policies` | 15 | |
| Traffic shaping | `/traffic-shaping/policies` (19), `/traffic-shaping/settings` | | |
| SSL VPN | `/ssl-vpn/global-settings` | | |
| Hotspots | `/wireless/hotspot/settings` | | |

Not found yet (404 on the guessed paths): NAT-independent ACL exception rules, unicast/multicast/SD-WAN routes, IPsec (connections, live, profiles), DoS, active threat response, application filter, hotspot list and vouchers, logging/syslog, SNMP, NetFlow, notification list, support access, SSL/TLS inspection, other certificate types.

## Rules for writing

- Every write action has a dry run, checks before writing (duplicates, pools, existing objects), reads back afterwards and logs what changed.
- Deleting only for objects the user names explicitly; Home Assistant never removes objects in bulk.
- Never write to administration, API access, support access, authentication or passwords.
- New write features are tested first on an object that is not in use (like `GuestAccess_DHCP`), on HA-test.

## Permissions

Since 25 November 2026 the API profile `HA-API` has read access on every category (set by Stefaan); `GET /administration/system-settings` now returns 200. The paths that still return 404 are wrong guesses, not missing permissions.
Write access is not granted yet. It will be added per category, only for the categories that get write features (first DHCP, then firewall rules).
