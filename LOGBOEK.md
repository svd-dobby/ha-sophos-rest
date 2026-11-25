# Logboek ha-sophos-rest

Eigen logboek voor de ontwikkeling van de integratie `sophos_rest`, los van het HA-logboek (`/config/logboek/overzicht.md` op prod). Nieuwste bovenaan. Werk het bij na elke stap.

## Afspraken

- Repo privé: `svd-dobby/ha-sophos-rest`. Nooit sleutels, wachtwoorden of interne IP-adressen in de repo.
- Domein `sophos_rest`. Vervangt later de integratie `sophos_firewall` (XML-API). Die wordt pas uitgeschakeld en daarna verwijderd na akkoord van Stefaan.
- Ontwikkelen en testen op HA-test (192.168.1.77). Prod pas na akkoord.
- Schrijven naar de firewall alleen met een uitdrukkelijke actie, eerst als droge proef, en eerst enkel op `GuestAccess_DHCP` (niet in gebruik).
- Firewall: Sophos XGS138, SFOS 23.0.0 GA-Build371. API-gebruiker `ha-api`, profiel `HA-API`. Sleutel staat als `sophos_rest_key` in secrets.yaml (prod en test) en wordt in de config flow ingevoerd.
- Updates: de Marketplace (HACS, ingebouwd sinds HA 2026.11) werkt alleen met publieke repo's. Bij een privé-repo komen updates via een eigen update-entiteit (gepland, stap 5) of via een sync-script.

## API-weetjes

- Basis `https://host:4444/api/firewall-config/v1`, header `Authorization: Bearer <sleutel>`.
- Documentatie: https://docs.sophos.com/nsg/sophos-firewall/rest-api/
- Lijsten komen terug als `{"items": [...]}`.
- `PATCH /network/dhcp/server/servers/ipv4/{naam}` met alleen `clientReservations` vervangt de hele lijst en laat de andere velden ongemoeid (getest 25 nov 2026).
- Een vaste reservering mag niet binnen een dynamisch bereik liggen (was voor v23 ook zo). De REST-API weigert met HTTP 400 `reservationOverlapWithPoolRange`.

## Stappenplan

1. Geraamte: config flow (host, poort, sleutel, certificaat), coordinator, sensor per DHCP-server, diagnostiek. Alleen lezen.
2. DHCP volledig lezen: reserveringen als entiteiten of attributen, actieve leases.
3. DHCP schrijven: acties `add_reservation` en `remove_reservation` met droge proef, controle op bereik en dubbels, teruglezen.
4. Andere API-groepen stap voor stap (interfaces, gateways, firewallregels, hosts, systeem).
5. Update-entiteit voor de privé-repo, daarna installatie op prod en `sophos_firewall` uitfaseren.

## Verloop

### 25 november 2026
- 21:08 [Claude] STAP 1 GETEST OP HA-TEST: Stefaan koppelde de integratie in de UI. sensor.sophos_192_168_1_254_dhcp_default_dhcp_server_reservations = 60 (enabled true, br0, 4 bereiken), sensor.sophos_192_168_1_254_dhcp_guestaccess_dhcp_reservations = 0. Geen fouten in de log. Opmerking: de entiteitsnamen komen uit de titel (host), later eventueel de firewallnaam (RedDwarf) gebruiken.
- 21:10 [Claude] 0.1.0 op HA-test gezet: bestanden via de File editor naar /config/custom_components/sophos_rest (groottes nagekeken, gelijk aan de repo), HA-test herstart. Geen fouten in de log. De koppeling toevoegen doet Stefaan zelf in de UI (de API-sleutel voert Claude niet in). Tijdelijke werkwijze: later een sync-script of de update-entiteit (stap 5).
- 21:00 [Claude] Eerste push naar GitHub (Claude-app kreeg toegang tot de repo).
- 20:40 [Claude] Repo-geraamte gemaakt, versie 0.1.0 (stap 1). Nog niet op HA-test geinstalleerd. Wacht op de lege repo op GitHub.
- 20:30 [Stefaan] Beslist: privé-repo `ha-sophos-rest`, eigen logboek, testen op HA-test, nieuwe integratie vervangt `sophos_firewall`.
