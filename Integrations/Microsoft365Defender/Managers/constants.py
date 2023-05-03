INTEGRATION_NAME = "Microsoft365Defender"
INTEGRATION_DISPLAY_NAME = "Microsoft 365 Defender"

# Actions
ADD_COMMENT_TO_INCIDENT_SCRIPT_NAME = "{} - Add Comment To Incident".format(INTEGRATION_DISPLAY_NAME)
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
UPDATE_INCIDENT_SCRIPT_NAME = "{} - Update Incident".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_QUERY_SCRIPT_NAME = "{} - Execute Query".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_ENTITY_QUERY_SCRIPT_NAME = "{} - Execute Entity Query".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_CUSTOM_QUERY_SCRIPT_NAME = "{} - Execute Custom Query".format(INTEGRATION_DISPLAY_NAME)

ACCESS_TOKEN_URL = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'

ENDPOINTS = {
    "login": "/{tenant_id}/oauth2/v2.0/token",
    "list_incidents": "/api/incidents",
    "update_incident": "/api/incidents/{incident_id}",
    "execute_query": "/api/advancedhunting/run",
    "get_alerts": "/v1.0/security/alerts_V2"
}

TOKEN_PAYLOAD = {
        'client_id': None,
        'client_secret': None,
        'scope': 'https://api.security.microsoft.com/.default',
        'grant_type': 'client_credentials'
    }

FILTER_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Connector
CONNECTOR_NAME = "{} - Incidents Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 10
DEFAULT_MAX_LIMIT = 20
DEFAULT_FETCH_INTERVAL = 6
INCIDENTS_LIMIT_PER_REQUEST = 100
ALERTS_LIMIT_PER_REQUEST = 250
DEVICE_VENDOR = "Microsoft"
DEVICE_PRODUCT = "Microsoft 365 Defender"
DEFAULT_CLASSIFICATION = "Unknown"

SEVERITY_MAP = {
    "Informational": -1,
    "Low": 40,
    "Medium": 60,
    "High": 80
}

SEVERITIES = ['informational', 'low', 'medium', 'high']

ENTITIES_KEY = 'entities'
DEVICES_KEY = 'devices'

EMPTY_DROPDOWN_VALUE = "Select One"

CLASSIFICATION_MAPPING = {
    "False Positive": "FalsePositive",
    "True Positive": "TruePositive"
}

DETERMINATION_MAPPING = {
    "Not Available": "NotAvailable",
    "Apt": "Apt",
    "Malware": "Malware",
    "Security Personnel": "SecurityPersonnel",
    "Security Testing": "SecurityTesting",
    "Unwanted Software": "UnwantedSoftware",
    "Other": "Other"
}

TIMEFRAME_MAPPING = {
    "Last Hour": {"hours": 1},
    "Last 6 Hours": {"hours": 6},
    "Last 24 Hours": {"hours": 24},
    "Last Week": "last_week",
    "Last Month": "last_month",
    "Custom": "custom"
}

DEFAULT_RESULTS_LIMIT = 50
OR_OPERATOR = "OR"
AND_OPERATOR = "AND"
ALERT_ID_KEY = "alert_id"

LIMIT_OF_INCIDENTS_TO_STORE = 1000
DEFAULT_INCIDENT_STATUS_FILTER = "Active, In Progress"
POSSIBLE_STATUSES = {
    "Active",
    "In Progress",
    "Resolved",
    "Redirected"
}
GRAPH_API_SCOPE = "https://graph.microsoft.com/.default"
TOO_MANY_REQUEST_TIMEOUT = 90 * 1000
FETCHING_TIMEOUT_TRESHOLD = 0.8
