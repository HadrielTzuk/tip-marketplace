PROVIDER_NAME = u'ObserveIT'
DEVICE_VENDOR = u'ObserveIT'
DEVICE_PRODUCT = u'ObserveIT'
ALERTS_LIMIT = 100
# Do not change the order, It's used in Manager._get_severities_from
SEVERITIES = [u'Low', u'Medium', u'High', u'Critical']


# REQUEST METHODS
GET = u'GET'
POST = u'POST'

# CONNECTORS
ALERTS_CONNECTOR_NAME = u'{} - Alerts Connector'.format(PROVIDER_NAME)
IDS_FILE = u'ids.json'
MAP_FILE = u'map.json'
ALERT_ID_FIELD = u'id'
LIMIT_IDS_IN_IDS_FILE = 1000
TIMEOUT_THRESHOLD = 0.9
ACCEPTABLE_TIME_INTERVAL_IN_MINUTES = 5
WHITELIST_FILTER = u'whitelist'
BLACKLIST_FILTER = u'blacklist'

# ACTIONS
PING_SCRIPT_NAME = u'{} - Ping'.format(PROVIDER_NAME)

# SIEM
OBSERVE_IT_TO_SIEM_SEVERITY = {
    u'Low': 40,
    u'Medium': 60,
    u'High': 80,
    u'Critical': 100
}