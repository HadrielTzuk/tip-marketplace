PROVIDER_NAME = u'Panorama'
DEVICE_VENDOR = u'Palo Alto'
DEVICE_PRODUCT = u'Panorama'
LOGS_LIMIT = 100

# REQUEST METHODS
GET = u'GET'
POST = u'POST'

# CONNECTORS
THREAT_LOG_CONNECTOR_NAME = u'{} - Threat Log Connector'.format(PROVIDER_NAME)
IDS_FILE = u'ids.json'
MAP_FILE = u'map.json'
THREAT_ID = u'threat_id'
LIMIT_IDS_IN_IDS_FILE = 1000
TIMEOUT_THRESHOLD = 0.9
ACCEPTABLE_TIME_INTERVAL_IN_MINUTES = 5
WHITELIST_FILTER = u'whitelist'
BLACKLIST_FILTER = u'blacklist'
CONNECTOR_LOG_TYPE = u'Threat'


ITEMS_PER_REQUEST = 50

HEADERS = {
    u'Accept': u'application/xml',
    u'Content-Type': u'application/x-www-form-urlencoded'
}
ENDPOINTS = {
    u'main_endpoint': u''
}

LOG_TYPE_MAP = {
    u'Traffic': u'traffic',
    u'Threat': u'threat',
    u'URL Filtering': u'url',
    u'WildFire Submissions': u'wildfire',
    u'Data Filtering': u'data',
    u'HIP Match': u'hipmatch',
    u'IP Tag': u'iptag',
    u'User ID': u'userid',
    u'Tunnel Inspection': u'tunnel',
    u'Configuration': u'config',
    u'System': u'system',
    u'Authentication': u'auth'
}

TIME_FORMAT = u'%Y/%m/%d %H:%M:%S'
JOB_FINISHED_STATUS = u'FIN'

# SIEM
PANORAMA_TO_SIEM_SEVERITY = {
    u'Informational': 20,
    u'Low': 40,
    u'Medium': 60,
    u'High': 80,
    u'Critical': 100
}

FILE_SUBTYPES = [
    u'file',
    u'virus',
    u'wildfire-virus',
    u'wildfire'
]

URI_SUBTYPE = u'url'

COMMIT_STATUS_FINISHED = u"FIN"
COMMIT_STATUS_FAILED = u"FAIL"

AMPERSAND_REPLACEMENT = "%26amp;"
AMPERSAND = "%26"
