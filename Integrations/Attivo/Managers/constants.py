INTEGRATION_NAME = "Attivo"
INTEGRATION_DISPLAY_NAME = "Attivo"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
UPDATE_EVENT_SCRIPT_NAME = "{} - Update Event".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = "{} - Enrich Entities".format(INTEGRATION_DISPLAY_NAME)
LIST_CRITICAL_THREATPATH_SCRIPT_NAME = "{} - List Critical ThreatPath".format(INTEGRATION_DISPLAY_NAME)
LIST_SERVICE_THREATPATHS_SCRIPT_NAME = "{} - List Service ThreatPaths".format(INTEGRATION_DISPLAY_NAME)
LIST_VULNERABILITY_HOSTS_SCRIPT_NAME = "{} - List Vulnerability Hosts".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "token": "/api/auth/login",
    "ping": "/api/eventsquery/alerts",
    "get_events": "/api/eventsquery/alerts",
    "update_event": "/api/eventsquery/action",
    "get_entity_info": "/api/query/fetch",
    "get_threatpaths": "/api/threatpath/getpathsforhostname",
    "get_vulnerabilities": "/api/threatpath/getvulforhostname",
    "get_credentials": "/api/threatpath/gethostdetails",
    "get_critical_threatpath": "/api/threatpath/getallcriticalpaths",
    "get_service_threatpaths": "/api/threatpath/getallpathsforservice",
    "get_vulnerability_hosts": "/api/threatpath/gethostnamesforvul"
}

SELECT_ONE = "Select One"
ACKNOWLEDGE_STATUS = "Acknowledge"
UNACKNOWLEDGE_STATUS = "Unacknowledge"
DEFAULT_ENTITIES_LIMIT = 50

EQUAL_FILTER = "Equal"
CONTAINS_FILTER = "Contains"
NOT_SPECIFIED_FILTER = "Not Specified"
FILTER_KEY_SELECT_ONE_FILTER = "Select One"
FILTER_KEY_MAPPING = {
    "Rule Name": "cr_rulename",
    "Service": "service",
    "Severity": "severity",
    "Description": "desc",
    "Category": "category"
}

# Connector
CONNECTOR_NAME = "{} - Events Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 100
DEFAULT_MAX_LIMIT = 1000
DEFAULT_FETCH_INTERVAL = 12
DEVICE_VENDOR = "Attivo"
DEVICE_PRODUCT = "Attivo"
RESULTS_MAX_COUNT = 25000

POSSIBLE_STATUSES = ["all", "acknowledged", "unacknowledged"]

SEVERITY_MAP = {
    "System Activity": -1,
    "Very Low": -1,
    "Low": 40,
    "Medium": 60,
    "High": 80,
    "Very High": 100
}

SEVERITIES = ['system activity', 'very low', 'low', 'medium', 'high', 'very high']

SEVERITY_START_MAP = {
    "System Activity": 0,
    "Very Low": 3,
    "Low": 4,
    "Medium": 7,
    "High": 11,
    "Very High": 14
}
