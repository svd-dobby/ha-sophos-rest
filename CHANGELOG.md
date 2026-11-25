# Changelog

## 0.2.0 (25 november 2026)
- Actieve DHCP-leases via `GET /network/dhcp/server/leases/ipv4` (met paginering via `pages.nextKey`, voor zover de firewall die geeft).
- Nieuwe sensoren: DHCP actieve leases (statisch en dynamisch, lijst als attribuut), DHCP dynamische leases (toestellen zonder vaste reservering), per server de vrije adressen in de dynamische bereiken.
- Reserveringssensor toont nu de lijst reserveringen (naam, MAC, IP) als attribuut. Grote lijsten worden niet in de recorder bewaard.
- Config flow vraagt een naam (standaard "Sophos Firewall") voor nieuwe koppelingen.
- Diagnostiek bevat ook de leases (MAC weggelaten).
- `tools/sophos_rest_sync.py`: zet de integratie vanuit deze repo op HA (deploy key, alleen lezen).

## 0.1.0 (25 november 2026)
- Eerste versie: config flow met herauthenticatie, coordinator (60 s), sensor per DHCPv4-server met het aantal reserveringen, diagnostiek zonder sleutel en MAC-adressen.
