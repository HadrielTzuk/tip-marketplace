INTEGRATION_NAME = u"Sophos"
INTEGRATION_DISPLAY_NAME = u"Sophos"

FILTER_TIME_FORMAT = u"%Y-%m-%dT%H:%M:%S.%fZ"

PING_SCRIPT_NAME = u"{} - Ping".format(INTEGRATION_NAME)
GET_SERVICE_STATUS_SCRIPT_NAME = u"{} - Get Service Status".format(INTEGRATION_NAME)
SCAN_ENDPOINTS_SCRIPT_NAME = u"{} - Scan Endpoints".format(INTEGRATION_NAME)
GET_EVENTS_LOG_SCRIPT_NAME = u"{} - GetEventsLog".format(INTEGRATION_NAME)
ISOLATE_ENDPOINT_SCRIPT_NAME = u"{} - Isolate Endpoint".format(INTEGRATION_NAME)
UNISOLATE_ENDPOINT_SCRIPT_NAME = u"{} - Unisolate Endpoint".format(INTEGRATION_NAME)
LIST_ALERT_ACTIONS_SCRIPT_NAME = u"{} - List Alert Actions".format(INTEGRATION_NAME)
EXECUTE_ALERT_ACTIONS_SCRIPT_NAME = u"{} - Execute Alert Actions".format(INTEGRATION_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = u"{} - Enrich Entities".format(INTEGRATION_NAME)
ADD_ENTITIES_TO_BLOCKLIST_ACTIONS_SCRIPT_NAME = u"{} - Add Entities To Blocklist".format(INTEGRATION_NAME)
ADD_ENTITIES_TO_ALLOWLIST_ACTIONS_SCRIPT_NAME = u"{} - Add Entities To Allowlist".format(INTEGRATION_NAME)

# Connector
CONNECTOR_NAME = u"{} - Alerts Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 10
MAX_LIMIT = 1000
MAX_FETCH_HOURS = 24
LIMIT_PER_REQUEST = 100
DEVICE_VENDOR = u"Sophos"
DEVICE_PRODUCT = u"Sophos Central"

SEVERITY_MAP = {
    u"low": 40,
    u"medium": 60,
    u"high": 100
}

SEVERITIES = [u'low', u'medium', u'high']

ISOLATED_JSON_RESPONSE = {u"enabled": True}
UNISOLATED_JSON_RESPONSE = {u"enabled": False}
ISOLATION_IN_PROGRESS = u"In Progress"
ISOLATED = u"Isolated"
UNISOLATED = u"Unisolated"
DEFAULT_TIMEOUT = 300
HEALTH_COLOR_MAP = {
    "Good": "#339966",
    "Suspicious": "#ff9900",
    "Bad": "#ff0000"
}

ACTION_TYPES_MAPPING = {
    "Acknowledge" : "acknowledge",
    "Clean PUA": "cleanPua",
    "Clean Virus": "cleanVirus",
    "Auth PUA": "authPua",
    "Clear Threat": "clearThreat",
    "Clear HMPA": "clearHmpa",
    "Send Message PUA": "sendMsgPua",
    "Send Message Threats": "sendMsgThreat"
}

SHA256_LENGTH = 64