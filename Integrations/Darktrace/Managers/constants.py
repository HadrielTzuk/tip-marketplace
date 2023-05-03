INTEGRATION_NAME = "Darktrace"
INTEGRATION_DISPLAY_NAME = "Darktrace"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_NAME = "{} - Enrich Entities".format(INTEGRATION_DISPLAY_NAME)
UPDATE_MODEL_BREACH_STATUS_SCRIPT_NAME = "{} - Update Model Breach Status".format(INTEGRATION_DISPLAY_NAME)
LIST_ENDPOINT_EVENTS_SCRIPT_NAME = "{} - List Endpoint Events".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_CUSTOM_SEARCH_SCRIPT_NAME = "{} - Execute Custom Search".format(INTEGRATION_DISPLAY_NAME)
LIST_SIMILAR_DEVICES_SCRIPT_NAME = "{} - List Similar Devices".format(INTEGRATION_DISPLAY_NAME)
ADD_COMMENT_TO_MODEL_BREACH_NAME = "{} - Add Comment To Model Breach".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "status": "/status",
    "model_breaches": "/modelbreaches",
    "model_breach_details": "/details",
    "device_search": "/devicesearch",
    "devices": "/devices",
    "endpoint_details": "/endpointdetails",
    "acknowledge": "/modelbreaches/{model_breach_id}/acknowledge",
    "unacknowledge": "/modelbreaches/{model_breach_id}/unacknowledge",
    "model_breach": "/modelbreaches/{model_breach_id}",
    "details": "/details",
    "connection_data": "/deviceinfo",
    "advanced_search": "/advancedsearch/api/search/{base64_query}",
    "similar_devices": "/similardevices",
    "add_comment": "/modelbreaches/{model_breach_id}/comments",
}


# Connector
CONNECTOR_NAME = "Darktrace - Model Breaches Connector"
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 10
DEFAULT_MAX_LIMIT = 100
MAX_LIMIT = 1000
DEFAULT_MIN_SCORE = 0
DEVICE_VENDOR = "Darktrace"
DEVICE_PRODUCT = "Darktrace"

SEVERITY_MAP = {
    "INFO": -1,
    "LOW": 40,
    "MEDIUM": 60,
    "HIGH": 80,
    "CRITICAL": 100
}


ENRICHMENT_PREFIX = "Dark"
DEVICE_KEYS = {
    "ip": "ip",
    "mac": "mac",
    "hostname": "hostname",
}

MODEL_BREACH_STATUSES = {
    "acknowledged": "Acknowledged",
    "unacknowledged": "Unacknowledged"
}

ERROR_TEXT = "ERROR"

PARAMETERS_DEFAULT_DELIMITER = ","
EVENT_TYPES = ["connection", "unusualconnection", "newconnection", "notice", "devicehistory", "modelbreach"]
EVENT_TYPES_NAMES = {
    "connection": "Connection Events",
    "unusualconnection": "Unusual Connection Events",
    "newconnection": "New Connection Events",
    "notice": "Notice Events",
    "devicehistory": "Device History Events",
    "modelbreach": "Model Breach Events"
}

TIMEFRAME_MAPPING = {
    "Last Hour": {"hours": 1},
    "Last 6 Hours": {"hours": 6},
    "Last 24 Hours": {"hours": 24},
    "Last Week": "last_week",
    "Last Month": "last_month",
    "Custom": "custom",
    "Alert Time Till Now": "Alert Time Till Now",
    "5 Minutes Around Alert Time": "5 Minutes Around Alert Time",
    "30 Minutes Around Alert Time": "30 Minutes Around Alert Time",
    "1 Hour Around Alert Time": "1 Hour Around Alert Time"
}

DEFAULT_MAX_HOURS_BACKWARDS = 24
DEFAULT_RESULTS_LIMIT = 50
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
