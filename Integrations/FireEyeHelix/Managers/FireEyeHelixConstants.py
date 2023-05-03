PROVIDER_NAME = 'FireEye Helix'
DEVICE_VENDOR = 'FireEye'
DEVICE_PRODUCT = 'FireEye Helix'
ALERTS_LIMIT = 50
NOTES_LIMIT = 50
ALERTS_FETCH_SIZE = 100
NEXT_PAGE_URL_KEY = 'next'
META_URL_KEY = 'meta'
QUERY_TYPE = 'json'
TIME_FORMAT = '%Y-%m-%d %H:%M:%S %p'
REQUEST_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
ENRICHMENT_PREFIX = 'FEHelix'

# Do not change the order, It's used in Manager._get_severities_from
SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
LOW_SEVERITY = 'Low'
DEFAULT_SEVERITY = 'Medium'

# CONNECTORS
ALERTS_CONNECTOR_NAME = '{} - Alerts Connector'.format(PROVIDER_NAME)
IDS_FILE = 'ids.json'
MAP_FILE = 'map.json'
ALERT_ID_FIELD = 'id'
LIMIT_IDS_IN_IDS_FILE = 1000
TIMEOUT_THRESHOLD = 0.9
ACCEPTABLE_TIME_INTERVAL_IN_MINUTES = 5
WHITELIST_FILTER = 'whitelist'
BLACKLIST_FILTER = 'blacklist'
DEFAULT_TIME_FRAME = 1

# ACTIONS
PING_SCRIPT_NAME = '{} - Ping'.format(PROVIDER_NAME)
SUPPRESS_ALERT_SCRIPT_NAME = '{} - Suppress Alert'.format(PROVIDER_NAME)
CLOSE_ALERT_SCRIPT_NAME = '{} - Close Alert'.format(PROVIDER_NAME)
ADD_NOTE_TO_ALERT_SCRIPT_NAME = '{} - Add Note To Alert'.format(PROVIDER_NAME)
GET_LISTS_SCRIPT_NAME = '{} - Get Lists'.format(PROVIDER_NAME)
GET_LIST_ITEMS_SCRIPT_NAME = '{} - Get List Items'.format(PROVIDER_NAME)
ADD_ENTITIES_TO_A_LIST = '{} - Add Entities To a List'.format(PROVIDER_NAME)
INDEX_SEARCH_SCRIPT_NAME = '{} - Index Search'.format(PROVIDER_NAME)
ARCHIVE_SEARCH_SCRIPT_NAME = '{} - Archive Search'.format(PROVIDER_NAME)
ENRICH_ENDPOINT_SCRIPT_NAME = '{} - Enrich Endpoint'.format(PROVIDER_NAME)
GET_ALERT_DETAILS_SCRIPT_NAME = '{} - Get Alert Details'.format(PROVIDER_NAME)
ENRICH_USER_SCRIPT_NAME = '{} - Enrich User'.format(PROVIDER_NAME)

# SIEM
FIREEYE_HELIX_TO_SIEM_SEVERITY = {
    'Low': 40,
    'Medium': 60,
    'High': 80,
    'Critical': 100
}

ENDPOINTS = {
    'test_connectivity': 'api/v3/appliances/health',
    'suppress_alert': 'api/v1/alerts/{alert_id}/suppress',
    'close_alert': 'api/v1/alerts/{alert_id}',
    'add_note': 'api/v3/alerts/{alert_id}/notes',
    'get_lists': 'api/v3/lists',
    'get_list_items': 'api/v3/lists/{list_id}/items',
    'get_alerts': 'api/v3/alerts/',
    'get_events': 'api/v3/alerts//{id}/events',
    'search': 'api/v1/search',
    'archive_search': 'api/v1/search/archive',
    'archive_search_results': 'api/v1/search/archive/{job_id}/results',
    'resume_archive_search': 'api/v1/search/archive/{job_id}/resume',
    'get_assets': 'api/v3/assets'
}

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'Mozilla/5.0'
}

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

SORT_BY_MAPPER = {
    'Name': 'name',
    'Short Name': 'short_name',
    'Created At': 'created_at',
}

SORT_ORDER_MAPPER = {
    'Ascending': '',
    'Descending': '-'
}

ITEM_TYPE_MAPPER = {
    'ALL': '',
    'Email': 'email',
    'FQDN': 'fqdn',
    'IPv4': 'ipv4',
    'IPv6': 'ipv6',
    'MD5': 'md5',
    'MISC': 'misc',
    'SHA-1': 'sha1'
}

ITEM_SORT_BY_MAPPER = {
    'Value': 'value',
    'Type': 'type',
    'Risk': 'risk',
}

ITEM_TYPES = {
    'email': 'email',
    'fqdn': 'fqdn',
    'ipv4': 'ipv4',
    'ipv6': 'ipv6',
    'md5': 'md5',
    'sha1': 'sha1',
    'misc': 'misc'
}

ACCEPTABLE_TIME_UNITS = {
    'd': 24,
    'h': 1
}

SHIFT_HOURS = 4

VALID_TIME_FRAME_PATTERN = "^(?!.*([dh]).*\1)\d+[dh](?: \d+[dh])*$"

JOB_FINISHED_STATUS = "complete"
JOB_PAUSED_STATUS = "paused"
