PROVIDER_NAME = u'Digital Shadows'

RESULTS_SIZE = 50

API_URL = u"https://portal-digitalshadows.com"
HEADERS = {u"Content-Type": u"application/json"}
API_ENDPOINTS = {
    u"SEARCH_FIND": u"/api/search/find",
    u'get_incidents': u'/api/incidents/find'
}

SEARCH_BODY = {
    u"pagination": {
        u"size": RESULTS_SIZE,
        u"offset": 0
    },
    u"sort": {
        u"property": u"relevance",
        u"direction": u"DESCENDING"
    },
    u"filter": {
        u"types": []
    },
    u"query": u"{}"
}


# CONNECTORS
DEVICE_VENDOR = u'Digital Shadows'
DEVICE_PRODUCT = u'Digital Shadows'
INCIDENTS_CONNECTOR_NAME = u'{} - Incident Connector'.format(PROVIDER_NAME)
IDS_FILE = u'ids.json'
MAP_FILE = u'map.json'
ALERT_ID_FIELD = u'id'
LIMIT_IDS_IN_IDS_FILE = 1000
TIMEOUT_THRESHOLD = 0.9
ACCEPTABLE_TIME_INTERVAL_IN_MINUTES = 5
WHITELIST_FILTER = u'whitelist'
BLACKLIST_FILTER = u'blacklist'
DEFAULT_TIME_FRAME = 1
ALERTS_FETCH_SIZE = 100
ALERTS_LIMIT = 50
DEFAULT_SEVERITY = u"NONE"
DATETIME_STR_FORMAT = u"%Y-%m-%dT%H:%M:%SZ"
API_MAX_FETCH_LIMIT = 500

# Do not change the order, It's used in Manager._get_severities_from
SEVERITIES = [u'NONE', u'VERY_LOW', u'LOW', u'MEDIUM', u'HIGH', u'VERY_HIGH']

# SIEM
DIGITAL_SHADOWS_TO_SIEM_SEVERITY = {
    u'NONE': -1,
    u'VERY_LOW': 40,
    u'LOW': 40,
    u'MEDIUM': 60,
    u'HIGH': 80,
    u'VERY_HIGH': 100
}