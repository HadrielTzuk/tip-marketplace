INTEGRATION_NAME = "Orca Security"
INTEGRATION_DISPLAY_NAME = "Orca Security"

# Actions
PING_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Ping"
UPDATE_ALERT_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Update Alert"
ADD_COMMENT_TO_ALERT_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Add Comment To Alert"
GET_COMPLIANCE_INFO_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Get Compliance Info"
SCAN_ASSETS_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Scan Assets"
GET_VULNERABILITY_DETAILS_SCRIPT_NAME = "{} - Get Vulnerability Details".format(INTEGRATION_DISPLAY_NAME)
GET_ASSET_DETAILS_SCRIPT_NAME = "{} - Get Asset Details".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "login": "/api/user/session",
    "ping": "/api/default_user_preference",
    "get_alerts": "/api/query/alerts",
    "verify_alert": "/api/alerts/{alert_id}/verify",
    "snooze_alert": "/api/alerts/{alert_id}/snooze",
    "update_alert_status": "/api/alerts/{alert_id}/status/{status}",
    "get_alert_data": "/api/alerts/{alert_id}",
    "add_alert_comment": "/api/alerts/{alert_id}/comment",
    "get_frameworks": "/api/compliance/frameworks/overview",
    "start_scan": "/api/scan/asset/{asset_id}",
    "get_scan_status": "/api/scan/status/{scan_id}",
    "vulnerability_details": "/api/query/cves",
    "asset_details": "/api/assets/{asset_id}"
}

# Connector
CONNECTOR_NAME = f"{INTEGRATION_DISPLAY_NAME} - Alerts Connector"
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 100
DEFAULT_MAX_LIMIT = 100
DEVICE_VENDOR = "Orca Security"
DEVICE_PRODUCT = "Orca Security"
WHITELIST_FILTER = 1
BLACKLIST_FILTER = 2
KEY_PREFIX = "Orca_Security"
FALLBACK_ALERT_NAME = "Orca Security Alert"
POSSIBLE_SEVERITIES = ["compromised", "imminent compromise", "hazardous", "informational"]
SEVERITY_MAPPING = {
    "compromised": 100,
    "imminent compromise": 80,
    "hazardous": 60,
    "informational": -1
}


DEFAULT_SNOOZE_DAYS = 1
SNOOZE_STATE_MAPPING = {
    "Select One": "",
    "Snooze": "Snooze",
    "Unsnooze": "Unsnooze"
}

STATUS_MAPPING = {
    "Select One": "",
    "Open": "open",
    "In Progress": "in_progress",
    "Close": "close",
    "Dismiss": "dismiss"
}

SCORE_MAPPING = {
    "info": 50,
    "low": 75,
    "medium": 90,
    "high": 100
}

SCORE_COLORS = {
    "info": "#ff0000",
    "low": "#ff9900",
    "medium": "#33cccc",
    "high": "#00ff00"
}

COMPLETED_STATUS = "done"
DEFAULT_TIMEOUT = 300

VULNERABILITIES_MAX_LIMIT = 10000
OUTPUT_TYPE_JSON = "JSON"
VULNERABILITIES_TABLE_NAME = "Vulnerability Details"
ASSETS_TABLE_NAME = "Asset Details"
SEVERITY_COLOR_MAPPER = {
    "compromised": "style='color: #ff0000;'",
    "imminent compromise": "style='color: #ff9900;'",
    "hazardous": "style='color: #ffff00;'",
    "informational": ""
}


