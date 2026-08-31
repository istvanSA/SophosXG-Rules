"""Constants for the Sophos XG Firewall Rule Control integration."""

DOMAIN = "sophos_xg_rules"

CONF_RULES = "rules"
CONF_VERIFY_SSL = "verify_ssl"

DEFAULT_PORT = 4444
DEFAULT_VERIFY_SSL = False

# How often to poll the firewall for the current status of tracked rules.
UPDATE_INTERVAL_SECONDS = 60

API_TIMEOUT = 20
