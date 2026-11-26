"""Constants for the Sophos REST integration."""

from datetime import timedelta

DOMAIN = "sophos_rest"

CONF_VERIFY_SSL = "verify_ssl"

DEFAULT_PORT = 4444
DEFAULT_VERIFY_SSL = False
DEFAULT_SCAN_INTERVAL = timedelta(seconds=60)
SNMP_SCAN_INTERVAL = timedelta(seconds=30)

CONF_SNMP_COMMUNITY = "snmp_community"
CONF_SNMP_PORT = "snmp_port"
DEFAULT_SNMP_PORT = 161

# DHCP servers on which the actions may write (chosen in the options; empty = none)
CONF_DHCP_WRITE_SERVERS = "dhcp_write_servers"

API_BASE = "/api/firewall-config/v1"
PATH_DHCP_SERVERS_V4 = "/network/dhcp/server/servers/ipv4"
PATH_DHCP_LEASES_V4 = "/network/dhcp/server/leases/ipv4"

PATH_SYSTEM_SETTINGS = "/administration/system-settings"
PATH_FIREWALL_RULES_V4 = "/firewall/rules/ipv4"
PATH_NAT_RULES_V4 = "/nat/rules/ipv4"
PATH_INTERFACES = "/network/interfaces/network-interfaces"
PATH_LIVE_USERS = "/authentication/live-users"
PATH_CERTIFICATES = "/certificate/certificates"
PATH_IPS_SETTINGS = "/intrusion-prevention/settings"
PATH_SPOOF_SETTINGS = "/spoof-protection/settings"
PATH_HOTFIX_SETTINGS = "/system/hotfix/settings"

DEFAULT_NAME = "Sophos Firewall"
