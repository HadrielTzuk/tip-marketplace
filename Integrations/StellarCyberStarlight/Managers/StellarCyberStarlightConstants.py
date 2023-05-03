PROVIDER_NAME = 'Stellar Cyber Starlight'

# ACTIONS
PING_SCRIPT_NAME = '{} - Ping'.format(PROVIDER_NAME)
SIMPLE_SEARCH_SCRIPT_NAME = '{} - Simple Search'.format(PROVIDER_NAME)
ADVANCED_SEARCH_SCRIPT_NAME = '{} - Advanced Search'.format(PROVIDER_NAME)
UPDATE_SECURITY_EVENT_SCRIPT_NAME = '{} - Update Security Event'.format(PROVIDER_NAME)

ENDPOINTS = {
    'test_connectivity': 'data/*/_search',
    'simple_search': 'data/{index}/_search',
    'get_alerts': 'data/aella-ser-*/_search',
    'update_event': 'update_ser',
}

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

ASCENDING_SORT = "Ascending"
DESCENDING_SORT = "Descending"
DEFAULT_LIMIT = 50
BAD_REQUEST_STATUS_CODE = 400

# CONNECTORS
DEVICE_VENDOR = 'Stellar Cyber'
DEVICE_PRODUCT = 'Starlight'
SECURITY_EVENTS_CONNECTOR_NAME = '{} - Security Events Connector'.format(PROVIDER_NAME)
ALERT_ID_FIELD = 'id'
ACCEPTABLE_TIME_INTERVAL_IN_MINUTES = 5
WHITELIST_FILTER = 'whitelist'
BLACKLIST_FILTER = 'blacklist'
DEFAULT_TIME_FRAME = 1
ALERTS_FETCH_SIZE = 100
ALERTS_LIMIT = 50
DEFAULT_SEVERITY = 50


STATUS_SELECT_ONE = "Select One"
