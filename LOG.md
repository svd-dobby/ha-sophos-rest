# Development log ha-sophos-rest

Log for the development of the `sophos_rest` integration, separate from the Home Assistant log (`/config/logboek/overzicht.md` on prod). Newest first. Update it after every step. Everything in this repository is written in English; the Home Assistant UI follows the user's language.

## Agreements

- Private repo `svd-dobby/ha-sophos-rest`. Never put keys, passwords or credentials in the repo.
- Domain `sophos_rest`. It will replace the `sophos_firewall` integration (XML API) later. That one is first disabled and then removed, each step only with Stefaan's approval.
- Develop and test on HA-test. Production only after approval.
- Writing to the firewall only through an explicit action, first as a dry run, and at first only on `GuestAccess_DHCP` (not in use).
- Firewall: Sophos XGS138, SFOS 23.0.0 GA-Build371. API user `ha-api`, profile `HA-API`. The key is stored as `sophos_rest_key` in secrets.yaml (prod and test) and entered in the config flow by Stefaan.
- Updates: the Marketplace (HACS, built into HA since 2026.11) only supports public repos. For this private repo, updates come through `tools/sophos_rest_sync.py` (read-only deploy key) and later an update entity (step 5).

## API notes

- Base `https://host:4444/api/firewall-config/v1`, header `Authorization: Bearer <key>`.
- Documentation: https://docs.sophos.com/nsg/sophos-firewall/rest-api/
- Lists are returned as `{"items": [...]}`; the leases list also has `pages` (`fromKey`, `size`, `maxSize`).
- `GET /network/dhcp/server/servers/ipv4`: servers with `addressPools` and `clientReservations` (`hostname`, `macAddress`, `ipv4Address`).
- `GET /network/dhcp/server/leases/ipv4`: active leases with `leasedStart`, `leasedEnd`, `leasedIp`, `macAddress`, `clientHostName`, `leaseType` (`static` or `dynamic`).
- `PATCH /network/dhcp/server/servers/ipv4/{name}` with only `clientReservations` replaces the whole list and leaves all other fields untouched (tested 25 Nov 2026).
- A static reservation must not lie inside a dynamic pool (this was already the case before v23). The REST API rejects it with HTTP 400 `reservationOverlapWithPoolRange`.
- `GET /administration/system-settings` returns 403 for profile HA-API (no read permission there). `/network/dhcp/server/settings` and `/system/hotfix` return 404.

## Plan

See ROADMAP.md for the breakdown per API category and priority.


1. Skeleton: config flow (host, port, key, certificate), coordinator, sensor per DHCP server, diagnostics. Read-only. Done (0.1.0).
2. Read DHCP completely: reservations, active leases, dynamic leases, free addresses. Done (0.2.0).
3. Write DHCP: actions `add_reservation` and `remove_reservation` with dry run, pool and duplicate checks, read-back.
4. Other API groups step by step (interfaces, gateways, firewall rules, hosts, system).
5. Update entity for the private repo, then installation on prod and phasing out `sophos_firewall`.

## History

### 25 November 2026
- 22:20 [Claude] 0.3.0 built (first read round, approved by Stefaan): paging, 403 handling, hostname as device name, binary sensors for firewall rules, NAT rules, interfaces and protection features, sensors for live users and certificate expiry. Field check: firewall and NAT rules have `enabled`; interfaces have only `enabled` (no link state); certificates come as base64 PEM.
- 22:05 [Claude] Stefaan opened read access on everything for profile HA-API. Probed about 130 guessed paths with read-only GET (via `sophos_dhcp.py rest_verken @file` on HA-test): 41 work, see ROADMAP.md. Findings: paging is `?pageSize=100&page=N` (default 50), so the client must page (address objects already have 52 items); gateways have no live status; `/administration/system-settings` now readable (hostname RedDwarf).
- 21:50 [Claude] ROADMAP.md added at Stefaan's request: API functions per category (read, create, update, delete) with priority, as a basis for choosing the order. Not yet verified per resource against the firewall.
- 21:33 [Claude] Checked on HA-test: the lists with IP and MAC addresses (`reservations`, `leases`, `devices`) are visible as attributes in HA but are not stored in the recorder (history shows only state, enabled, interface, pools). Stefaan: keep it that way (visible, not stored).
- 21:25 [Claude] Repository translated to English at Stefaan's request (code, README, changelog, this log, which was renamed from LOGBOEK.md to LOG.md). The HA UI follows the user's language through translations (en, nl). Sync script: English output, action `key`, updates itself on `pull`. Version 0.2.1.
- 21:20 [Claude] STEP 2 TESTED ON HA-TEST. Stefaan added the deploy key, `sophos_rest_sync test` OK, `pull` 0.1.0 to 0.2.0 (commit 10b28cf, backup in /config/git_repo/sophos_rest_bak), HA-test restarted, no errors. Values: active leases 59 (39 static, 20 dynamic), dynamic leases 20, free addresses Default_DHCP_Server 44 (pools total 64 addresses), GuestAccess_DHCP 155, reservations 60 and 0. Existing entity IDs unchanged. Next: step 3 (write DHCP, first on GuestAccess_DHCP).
- 21:14 [Claude] STEP 2 (0.2.0) built. Explored with `sophos_dhcp.py rest_verken` (read-only GET): the leases endpoint works (59 leases), see API notes for the 403 and 404 results.
- 21:12 [Claude] Sync script `tools/sophos_rest_sync.py` installed on HA-test as /config/scripts/sophos_rest_sync.py, with `shell_command.sophos_rest_sync` in HA-test's configuration.yaml, HA-test restarted. Deploy key /config/.ssh/ha_sophos_rest_deploy created (ed25519).
- 21:10 [Claude] 0.1.0 installed on HA-test: files written through the File editor to /config/custom_components/sophos_rest (sizes checked against the repo), HA-test restarted, no errors. Stefaan adds the config entry in the UI himself (Claude does not enter the API key).
- 21:08 [Claude] STEP 1 TESTED ON HA-TEST: Stefaan added the integration in the UI. `sensor.sophos_192_168_1_254_dhcp_default_dhcp_server_reservations` = 60 (enabled true, br0, 4 pools), `sensor.sophos_192_168_1_254_dhcp_guestaccess_dhcp_reservations` = 0. No errors in the log. Note: entity names come from the entry title (host); the entry can be renamed in the UI.
- 21:00 [Claude] First push to GitHub (the Claude app was given access to the repo).
- 20:40 [Claude] Repository skeleton created, version 0.1.0 (step 1).
- 20:30 [Stefaan] Decided: private repo `ha-sophos-rest`, own log, test on HA-test, the new integration replaces `sophos_firewall`.
