INTEGRATION_NAME = "BMC Helix Remedyforce"
INTEGRATION_IDENTIFIER = "BMCHelixRemedyForce"
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
CREATE_RECORD_ACTION = '{} - Create Record'.format(INTEGRATION_NAME)
DELETE_RECORD_ACTION = '{} - Delete Record'.format(INTEGRATION_NAME)
UPDATE_RECORD_ACTION = '{} - Update Record'.format(INTEGRATION_NAME)
GET_RECORD_DETAILS_ACTION = '{} - Get Record Details'.format(INTEGRATION_NAME)
EXECUTE_CUSTOM_QUERY_ACTION = '{} - Execute Custom Query'.format(INTEGRATION_NAME)
LIST_RECORD_TYPES_ACTION = '{} - List Record Types'.format(INTEGRATION_NAME)
WAIT_FOR_FIELD_UPDATE_ACTION = '{} - Wait For Field Update'.format(INTEGRATION_NAME)
EXECUTE_SIMPLE_ACTION = '{} - Execute Simple Query'.format(INTEGRATION_NAME)
GET_AUTHORIZATION_SCRIPT_NAME = '{} - Get OAuth Authorization Code'.format(INTEGRATION_NAME)
GENERATE_TOKEN_SCRIPT_NAME = '{} - Get OAuth Refresh Token'.format(INTEGRATION_NAME)

ENDPOINTS = {
    'test_connectivity': '/services/data/v51.0/query/?q=SELECT FIELDS(ALL) from Account LIMIT 1',
    'get_session_id': '/services/Soap/u/35.0',
    'create_record': '/services/data/v51.0/sobjects/{record_type}',
    'manage_record': '/services/data/v51.0/sobjects/{record_type}/{record_id}',
    'execute_query': '/services/data/v51.0/query/',
    'get_objects': '/services/data/v51.0/sobjects/',
    'get_incidents': '/services/data/v51.0/query/',
    'login': '/services/oauth2/token'
}

OAUTH_URL = "https://login.salesforce.com/services/oauth2/token"

EQUAL_FILTER = "Equal"
CONTAINS_FILTER = "Contains"

# Connector
CONNECTOR_NAME = "{} - Incidents Connector".format(INTEGRATION_NAME)
DEFAULT_PRIORITY = 5
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 10
MAX_LIMIT = 200
LIMIT_PER_REQUEST = 100
DEVICE_VENDOR = "BMC Helix Remedyforce"
DEVICE_PRODUCT = "BMC Helix Remedyforce"
API_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

SEVERITY_MAP = {
    "5": -1,
    "4": 40,
    "3": 60,
    "2": 80,
    "1": 100
}
ASYNC_ACTION_TIMEOUT_THRESHOLD_MS = 30 * 1000

TIME_FRAME_LAST_HOUR = "Last Hour"
TIME_FRAME_LAST_6HOURS = "Last 6 Hours"
TIME_FRAME_LAST_24HOURS = "Last 24 Hours"
TIME_FRAME_LAST_WEEK = "Last Week"
TIME_FRAME_LAST_MONTH = "Last Month"
TIME_FRAME_CUSTOM = "Custom"

SORT_ORDER_ASC = "ASC"
SORT_ORDER_DESC = "DESC"

LIMIT_MAX = 200
