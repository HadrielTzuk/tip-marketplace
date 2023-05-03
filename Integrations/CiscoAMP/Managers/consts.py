# Security Events Connector
SECURITY_EVENTS_CONNECTOR_NAME = u"Cisco AMP - Security Events Connector"

MAX_EVENTS_PAGE_LIMIT = 500
DEFAULT_EVENTS_PAGE = 100
MAX_EVENTS = 1000
DEFAULT_TIME_FRAME = 1
DEFAULT_MAX_LIMIT = 100
SEVERITIES = [u"Low", u"Medium", u"High", u"Critical"]
DEVICE_VENDOR = u"Cisco"
DEVICE_PRODUCT = u"Cisco AMP"
STORED_IDS_LIMIT = 3000
EVENT_ID_FIELD = u"id"

SEVERITY_TO_SIEM = {
    u"Info": -1,
    u"Low": 40,
    u"Medium": 60,
    u"High": 80,
    u"Critical": 100
}

SEVERITIES_MAP = {
    u"Low": (u"Low", u"Medium", u"High", u"Critical"),
    u"Medium": (u"Medium", u"High", u"Critical"),
    u"High": (u"High", u"Critical"),
    u"Critical": (u"Critical",)
}

# Manager
LIMIT = 500
HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Accept-Encoding': 'gzip'
}
