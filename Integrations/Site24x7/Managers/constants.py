INTEGRATION_NAME = "Site24x7"
INTEGRATION_DISPLAY_NAME = "Site24x7"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
GENERATE_REFRESH_TOKEN_SCRIPT_NAME = "{} - Generate Refresh Token".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "token": "/oauth/v2/token",
    "ping": "/api/monitors",
    "monitors": "/api/monitors",
    "alert_logs": "/api/alert_logs"
}

ACCESS_TOKEN_PAYLOAD = {
        'client_id': None,
        'client_secret': None,
        'refresh_token': None,
        'grant_type': 'refresh_token'
    }

REFRESH_TOKEN_PAYLOAD = {
        'client_id': None,
        'client_secret': None,
        'code': None,
        'grant_type': 'authorization_code'
    }

API_ROOT_TO_AUTH_URL = {
    "https://www.site24x7.com": "https://accounts.zoho.com",
    "https://www.site24x7.eu": "https://accounts.zoho.eu",
    "https://www.site24x7.cn": "https://accounts.zoho.com.cn",
    "https://www.site24x7.in": "https://accounts.zoho.in",
    "https://www.site24x7.net.au": "https://accounts.zoho.com.au"
}

# Connector
CONNECTOR_NAME = "{} - Alerts Log Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 100
REQUEST_DATE_FORMAT = '%Y-%m-%d'
API_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
DEVICE_VENDOR = "Site24x7"
DEVICE_PRODUCT = "Site24x7"

SEVERITY_MAP = {
    "Up": -1,
    "Trouble": 80,
    "Down": 100,
    "Critical": 100
}

ALERT_TYPE_MAP = {
    1: "EMAIL",
    2: "SMS",
    3: "VOICE",
    4: "CHAT",
    5: "ALARMSONE",
    6: "SDPOD",
    7: "SLACK",
    8: "HIPCHAT",
    9: "PAGERDUTY",
    10: "SDP",
    11: "WEBHOOK",
    12: "MICROSOFT_TEAMS",
    13: "OPSGENIE",
    14: "SERVICENOW",
    15: "STRIDE",
    16: "SDPMSP",
    17: "ZAPIER",
    18: "CONNECTWISE",
    19: "ZANALYTICS",
    20: "JIRA",
    21: "MOOGSOFT"
}

DOWN_STATUS = "Down"
UP_STATUS = "Up"
CRITICAL_STATUS = "Critical"
TROUBLE_STATUS = "Trouble"

ERROR_WORD = "error"
