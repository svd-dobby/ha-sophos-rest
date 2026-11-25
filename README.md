# Sophos Firewall (REST) voor Home Assistant

Custom integratie `sophos_rest` voor de REST-API van Sophos Firewall (SFOS v23 en later).

## Stand

Versie 0.1.0: alleen lezen. Per DHCPv4-server een sensor met het aantal vaste reserveringen (attributen: actief, interface, bereiken).

## Installatie (handmatig)

1. Kopieer `custom_components/sophos_rest` naar `/config/custom_components/`.
2. Herstart Home Assistant.
3. Instellingen > Apparaten en diensten > Integratie toevoegen > "Sophos Firewall (REST)".
4. Vul host, poort (standaard 4444) en de API-sleutel in (Administration > API access op de firewall).

Zie `LOGBOEK.md` voor het verloop en `CHANGELOG.md` voor de versies.
