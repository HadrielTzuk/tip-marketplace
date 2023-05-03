INTEGRATION_NAME = "Extrahop"
INTEGRATION_DISPLAY_NAME = "Extrahop"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "token": "/oauth2/token",
    "ping": "/api/v1/devices?search_type=ip address&limit=1",
    "get_detections": "/api/v1/detections/search",
    "get_device_details": "/api/v1/devices/{device_id}"
}

# Connector
CONNECTOR_NAME = "{} - Detections Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 100
DEVICE_VENDOR = "Extrahop"
DEVICE_PRODUCT = "Extrahop"
DEVICE_OBJECT_TYPE = "device"
ALERT_ID_KEY = "id"
