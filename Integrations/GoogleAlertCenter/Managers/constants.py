INTEGRATION_NAME = "Google Alert Center"
INTEGRATION_DISPLAY_NAME = "Google Alert Center"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
DELETE_ALERT_SCRIPT_NAME = "{} - Delete Alert".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping": "alerts?pageSize={limit}",
    "alerts": 'alerts?pageSize={limit}&orderBy=createTime asc&filter=createTime >= "{timestamp}"',
    "delete_alert": "alerts/{alert_id}"
}

GOOGLE_APIS_ALERTS_ROOT = "https://alertcenter.googleapis.com/v1beta1/"
SCOPES = ["https://www.googleapis.com/auth/apps.alerts"]

SUCCESS_STATUSES = ["200"]


# Connector
CONNECTOR_NAME = "Google Alert Center - Alerts Connector"
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 100
DEFAULT_MAX_LIMIT = 100
DEVICE_VENDOR = "Google"
DEVICE_PRODUCT = "Google Alert Center"
CONNECTOR_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

SEVERITY_MAP = {
    "informational": -1,
    "low": 40,
    "medium": 60,
    "high": 80
}
