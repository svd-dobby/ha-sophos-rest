"""Constants for the Sophos REST integration."""

from datetime import timedelta

DOMAIN = "sophos_rest"

CONF_VERIFY_SSL = "verify_ssl"

DEFAULT_PORT = 4444
DEFAULT_VERIFY_SSL = False
DEFAULT_SCAN_INTERVAL = timedelta(seconds=60)

API_BASE = "/api/firewall-config/v1"
PATH_DHCP_SERVERS_V4 = "/network/dhcp/server/servers/ipv4"
PATH_DHCP_LEASES_V4 = "/network/dhcp/server/leases/ipv4"

DEFAULT_NAME = "Sophos Firewall"
