# Sophos Firewall (REST) for Home Assistant

Custom integration `sophos_rest` for Sophos Firewall (SFOS v23 and later). It reads the firewall configuration through the REST API and the live values through SNMP. A few carefully guarded actions can change the DHCP configuration.

Current version: **0.10.1**. It is tested on a test Home Assistant against an XGS 138 with SFOS 23.0. It is meant to replace the core `sophos_firewall` integration (XML API).

## What it provides

The entities are grouped into sub-devices under one firewall device.

| Device | Source | Entities |
|---|---|---|
| Firewall (main) | REST, SNMP | CPU, memory, swap and disk use, CPU and NPU temperature, fan speed, last boot, firmware, IPS and web category versions, logged-in users |
| DHCP | REST | Per server: reservations (with a list), free addresses in the dynamic pools, active leases, dynamic leases (devices without a reservation) |
| Firewall rules | REST | One binary sensor per rule (on = enabled) |
| NAT rules | REST | One binary sensor per rule (on = enabled) |
| Interfaces | REST, SNMP | Enabled, live link state, bytes received and sent, PoE power per port |
| Security | REST | Intrusion prevention, spoof protection, automatic hotfixes, days until each certificate expires |
| Services | SNMP | One binary sensor per firewall service (on = running) |
| Licences | SNMP | Expiry date per subscription (a perpetual licence shows 31 December 2999) |
| VPN | SNMP | One binary sensor per IPsec connection |

Entity and device names follow the Home Assistant language (English and Dutch included).

Lists with IP and MAC addresses are visible as attributes but are **not stored** in the recorder history. Diagnostics hide the API key, MAC addresses, the SNMP community and the serial number.

## SNMP traps

When "Receive SNMP traps" is on in the options, the integration listens on UDP (port 162 by default) for traps from the firewall. It accepts SNMP v1 and v2c, but only from the firewall's address and with the SNMP community. Every trap fires the event `sophos_rest_trap`:

```yaml
triggers:
  - trigger: event
    event_type: sophos_rest_trap
```

The event data holds `trap_oid`, `trap_name` (for standard traps such as `link_down`), `version`, `alert_id` and `alert_text` (Sophos alerts), `message` (the readable text), `varbinds`, `uptime` and `config_entry_id`. Sophos sends every alert with the same trap OID, so trigger on the text, for example with a template condition on `trigger.event.data.alert_text`. The sensor "Last SNMP trap" shows the time of the last trap, with the trap and the counters as attributes.

On the firewall: turn on SNMP traps in the notification list, choose per notification what to send, and add this Home Assistant as trap receiver in the SNMP settings.

## Actions (write)

All actions:

- work only on DHCP servers ticked in the integration options (none by default);
- support `dry_run`, which checks and reports without writing;
- write a single field (PATCH), read the server back and verify that the change is as expected and that nothing else changed;
- return the result as action response.

| Action | What it does |
|---|---|
| `sophos_rest.add_dhcp_reservation` | Adds a reservation (name, MAC, IP). Refused when the IP lies in a dynamic pool or the MAC or IP is already used. |
| `sophos_rest.remove_dhcp_reservation` | Removes exactly one reservation, by MAC and/or IP. |
| `sophos_rest.set_dhcp_pools` | Replaces the dynamic pools. Refused when pools overlap or a reservation would lie inside a pool. Lists the dynamic leases that fall outside the new pools. |
| `sophos_rest.set_dhcp_lease_time` | Sets the default and maximum lease time in minutes. This is useful for a short lease time while addresses move. |

## Permissions on the firewall

Create an API key under Administration > API access, with a profile that allows what you need. Every part is optional:

- An HTTP 403 means the key is valid but has no permission for that part. Only that part is left out.
- Only an HTTP 401 asks for a new key.

| Profile permission | Needed for |
|---|---|
| Network, read | DHCP and interfaces |
| Network, read-write | The DHCP actions |
| Read on the matching category | Every other part (rules, users, certificates, protection, system settings) |

Read access on every category is the simplest choice. The integration never writes authentication, administration, API access or passwords.

SNMP v2c is optional and read-only. Set the community in the integration options; an empty community turns SNMP off. The integration has its own minimal SNMP client and needs no extra Python packages.

## Installation

### Manual

1. Copy `custom_components/sophos_rest` to `/config/custom_components/`.
2. Restart Home Assistant.
3. Go to Settings > Devices & services > Add integration > "Sophos Firewall (REST)".
4. Enter a name, the host, the port (default 4444) and the API key.
5. Optional: open the integration options and fill in the SNMP community and the DHCP servers that may be changed.

### From this private repo

`tools/sophos_rest_sync.py` installs and updates the integration straight from GitHub with a read-only deploy key. It runs from a `shell_command` in Home Assistant:

| Command | What it does |
|---|---|
| `key` | Creates the deploy key and shows the public part to add on GitHub |
| `test` | Checks access to the repo |
| `status` | Shows the installed version |
| `pull [ref]` | Installs the latest version, or a given branch, tag or commit |

`pull` keeps a backup of the previous version and also updates the script itself. Restart Home Assistant after a `pull`.

HACS and the built-in marketplace only support public repos, so they cannot install from this repo.

## More

- `CHANGELOG.md`: what changed per version.
- `ROADMAP.md`: API functions per category with priority, verified read endpoints, the SNMP data map and the permissions.
- `LOG.md`: the development log, with agreements, API notes and open items.
