INTEGRATION_NAME = "Splash"
INTEGRATION_DISPLAY_NAME = "Splash"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_ACTION = "{} - Enrich Entities".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping": "/_ping",
    "get_data": "/render.json"
}

CA_CERTIFICATE_FILE_PATH = "cacert.pem"
HTTP_SCHEMA = "http://"
HTTPS_SCHEMA = "https://"
