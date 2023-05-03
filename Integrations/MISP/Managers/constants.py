DEFAULT_HOURS_BACKWARDS = 24
HOURS_LIMIT_IN_IDS_FILE = 72
STORED_IDS_LIMIT = 10000
TIMEOUT_THRESHOLD = 0.9
DEFAULT_PRODUCT = "MISP"
DEFAULT_VENDOR = "MISP"
RULE_GENERATOR = "MISP Events"
TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
CONNECTOR_NAME = 'MISP - Attributes Connector'

INTEGRATION_NAME = 'MISP'
DATA_ENRICHMENT_PREFIX = 'MISP'
DATA_ATTRIBUTE_ENRICHMENT_PREFIX = 'MISP_attribute'


# ACTION NAMES
PUBLISH_EVENT_SCRIPT_NAME = '{} - Publish Event'.format(INTEGRATION_NAME)
UNPUBLISH_EVENT_SCRIPT_NAME = '{} - Unpublish Event'.format(INTEGRATION_NAME)
GET_EVENT_DETAILS_SCRIPT_NAME = '{} - Get Event Details'.format(INTEGRATION_NAME)
CREATE_EVENT_SCRIPT_NAME = '{} - Create Event'.format(INTEGRATION_NAME)
DELETE_EVENT_SCRIPT_NAME = '{} - Delete Event'.format(INTEGRATION_NAME)
REMOVE_TAG_FROM_AN_EVENT_SCRIPT_NAME = '{} - Remove Tag from an Event'.format(INTEGRATION_NAME)
REMOVE_TAG_FROM_AN_ATTRIBUTE = '{} - Remove Tag from an Attribute'.format(INTEGRATION_NAME)
ADD_TAG_TO_AN_ATTRIBUTE = '{} - Add Tag to an Attribute'.format(INTEGRATION_NAME)
ADD_TAG_TO_AN_EVENT_SCRIPT_NAME = '{} - Add Tag to an Event'.format(INTEGRATION_NAME)
UPLOAD_FILE_SCRIPT_NAME = '{} - Upload File Details'.format(INTEGRATION_NAME)
LIST_EVENT_OBJECTS_SCRIPT_NAME = '{} - List Event Objects'.format(INTEGRATION_NAME)
CREATE_VTREPORT_OBJECT_SCRIPT_NAME = '{} - Create Virustotal-Report Object'.format(INTEGRATION_NAME)
CREATE_FILE_OBJECT_SCRIPT_NAME = '{} - Create File Misp Object'.format(INTEGRATION_NAME)
CREATE_NETWORK_CONNECTION_MISP_OBJECT_SCRIPT_NAME = '{} - Create network-connection Misp Object'\
    .format(INTEGRATION_NAME)
CREATE_IPPORT_OBJECT_SCRIPT_NAME = '{} - Create IP-Port Misp Object'.format(INTEGRATION_NAME)
CREATE_URL_OBJECT_SCRIPT_NAME = '{} - Create Url Misp Object'.format(INTEGRATION_NAME)
LIST_SIGHTINGS_OF_AN_ATTRIBUTE_SCRIPT_NAME = '{} - List Sightings of an Attribute'.format(INTEGRATION_NAME)
DELETE_AN_ATTRIBUTE_SCRIPT_NAME = '{} - Delete an Attribute'.format(INTEGRATION_NAME)
SET_IDS_FLAG_ON_AN_ATTRIBUTE_SCRIPT_NAME = '{} - Set IDS flag on an Attribute'.format(INTEGRATION_NAME)
UNSET_IDS_FLAG_ON_AN_ATTRIBUTE_SCRIPT_NAME = '{} - Unset IDS flag on an Attribute'.format(INTEGRATION_NAME)
ADD_ATTRIBUTE_SCRIPT_NAME = '{} - Add Attribute'.format(INTEGRATION_NAME)
DOWNLOAD_FILE_SCRIPT_NAME = '{} - Download File'.format(INTEGRATION_NAME)
GET_RELATED_EVENTS_SCRIPT_NAME = '{} - Get Related Events'.format(INTEGRATION_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = '{} - Enrich Entities'.format(INTEGRATION_NAME)
ADD_SIGHTING_TO_AN_ATTRIBUTE_SCRIPT_NAME = '{} - Add Sighting to an Attribute'.format(INTEGRATION_NAME)

EMAIL_PATTERN = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
SSDEEP_HASH_PATTERN = r"((\d*):(\w*):(\w*)|(\d*):(\w*)\+(\w*):(\w*))"
DOMAIN_PATTERN = r"[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+"


# ADDITIONAL ENTITY TYPES
EMAIL_TYPE = 101
DOMAIN_TYPE = 102

COMMUNITY = 'community'
ORGANIZATION = 'organisation'
CONNECTED = 'connected'
ALL = 'all'
INHERIT = 'inherit'

DISTRIBUTION = {
    ORGANIZATION: 0,
    COMMUNITY: 1,
    CONNECTED: 2,
    ALL: 3
}

ATTRIBUTE_DISTRIBUTION = {
    ORGANIZATION: 0,
    COMMUNITY: 1,
    CONNECTED: 2,
    ALL: 3,
    INHERIT: 5
}

HIGH = 'high'
MEDIUM = 'medium'
LOW = 'low'
UNDEFINED = 'undefined'

THREAT_LEVEL = {
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    UNDEFINED: 4
}

INITIAL = 'initial'
ONGOING = 'ongoing'
COMPLETED = 'completed'

ANALYSIS = {
    INITIAL: 0,
    ONGOING: 1,
    COMPLETED: 2
}

ALL_EVENTS = 'all'
PROVIDED_EVENT = 'provided'

ATTRIBUTE_SEARCH_MAPPER = {
    ALL_EVENTS: 'All Events',
    PROVIDED_EVENT: 'Provided Event'
}

EXISTING_CATEGORY_TYPES = ['external analysis', 'payload delivery', 'artifacts dropped', 'payload installation']
ATTRIBUTES_EXISTING_CATEGORY_TYPES = ["targeting data", "payload delivery", "artifacts dropped", "payload installation",
                                      "persistence mechanism", "network activity", "attribution",
                                      "external analysis", 'social network']

SOURCE_IP = 1
DESTINATION_IP = 2

IP_TYPE = {
    SOURCE_IP: 'Source IP',
    DESTINATION_IP: 'Destination IP'
}

HASH_TYPES_WITH_LEN_MAPPING = {
    32: 'md5',
    40: 'sha1',
    56: 'sha224',
    64: 'sha256',
    96: 'sha384',
    128: 'sha512',
}

NETWORK_CONNECTION_TABLE_NAME = "New Event {} Network-Connection Objects"
FILE_OBJECT_TABLE_NAME = 'New Event {} File Objects'
ATTRIBUTE_LIST_SIGHTINGS_TABLE_NAME = 'Latest Sightings for the {}'
LAST = 'LAST'
FIRST = 'FIRST'

# CASE WALL CONSTANTS
EVENT_OBJECT_TABLE_NAME = 'Event {} Objects'
CASE_WALL_DOWNLOADED_FILES_TITLE = "Event {} Files"
EVENT_URL_OBJECT_TABLE_NAME = 'New Event {0} URL Objects'
IPPORT_TABLE_NAME = 'New Event {} IP-Port Objects'
VTREPORT_TABLE_NAME = "New Event {} VirusTotal Report Object"
RELATED_EVENTS_TABLE_NAME = '{} - Related Events'
ATTRIBUTE_INSIGHT_NAME = "Attribute Comment: {}"
ATTRIBUTE_TABLE_NAME = '{} - Attributes'

FALLBACK_IP_TYPES_MAPPER = {
    'ip-src': 'Source Address',
    'ip-dst': 'Destination Address'
}

IP_TYPES = {
    FALLBACK_IP_TYPES_MAPPER['ip-src']: 'ip-src',
    FALLBACK_IP_TYPES_MAPPER['ip-dst']: 'ip-dst'
}

FALLBACK_EMAIL_TYPES_MAPPER = {
    'email-src': 'Source Email Address',
    'email-dst': 'Destination Email Address'
}

EMAIL_TYPES = {
    FALLBACK_EMAIL_TYPES_MAPPER['email-src']: 'email-src',
    FALLBACK_EMAIL_TYPES_MAPPER['email-dst']: 'email-dst'
}

# DEFAULTS
ATTRIBUTES_LIMIT_DEFAULT = 10

