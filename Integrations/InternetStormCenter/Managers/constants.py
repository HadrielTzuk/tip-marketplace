INTEGRATION_NAME = "InternetStormCenter"
INTEGRATION_DISPLAY_NAME = "Internet Storm Center"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = "{} - Enrich Entities".format(INTEGRATION_NAME)

API_ROOT = "http://isc.sans.edu"
ENDPOINTS = {
    "ping": "/api/handler?json=null",
    "get_device": "/api/ip/{address}?json=null"
}

DEFAULT_TIMEOUT = 300
