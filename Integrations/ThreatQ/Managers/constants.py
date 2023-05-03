INTEGRATION_NAME = 'ThreatQ'
INTEGRATION_PREFIX = 'TQ'
LINK_OBJECTS_SCRIPT = '{} - Link Objects'.format(INTEGRATION_NAME)
CREATE_ADVERSARY_SCRIPT = '{} - Create Adversary'.format(INTEGRATION_NAME)
CREATE_INDICATOR_SCRIPT = '{} - Create Indicator'.format(INTEGRATION_NAME)
LIST_RELATED_OBJECTS_SCRIPT = '{} - List Related Objects'.format(INTEGRATION_NAME)
ADD_ATTRIBUTE_SCRIPT = '{} - Add Attribute'.format(INTEGRATION_NAME)
ADD_SOURCE_SCRIPT = '{} - Add Source'.format(INTEGRATION_NAME)
GET_MALWARE_DETAILS = '{} - Get Malware Details'.format(INTEGRATION_NAME)
CREATE_OBJECT_SCRIPT = '{} - Create Object'.format(INTEGRATION_NAME)
LIST_ENTITY_RELATED_OBJECTS_SCRIPT = '{} - List Entity Related Objects'.format(INTEGRATION_NAME)
CREATE_EVENT_SCRIPT = '{} - Create Event'.format(INTEGRATION_NAME)
UPDATE_INDICATOR_STATUS = '{} - Update Indicator Status'.format(INTEGRATION_NAME)
LINK_ENTITIES_SCRIPT = '{} - Link Entities'.format(INTEGRATION_NAME)
LINK_ENTITIES_TO_OBJECTS_SCRIPT = '{} - Link Entities To Objects'.format(INTEGRATION_NAME)
UPDATE_INDICATOR_SCORE = '{} - Update Indicator Score'.format(INTEGRATION_NAME)
LIST_EVENTS_SCRIPT = '{} - List Events'.format(INTEGRATION_NAME)

HAPPENED_AT_DATETIME_DEFAULT_FORMAT = u"%Y-%m-%d %H:%M:%S"
EMAIL_REGEX = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,63}$"
THREATQ_PREFIX = u"TQ"

ADDITIONAL_FIELDS_LIST = ["adversaries", "attachments", "attributes", "comments", "events", "indicators", "signatures", "sources", "spearphish", "tags", "type", "watchlist"]

ASCENDING_SORT = u'Ascending'

INDICATOR_TYPE_MAPPING = {
    'ASN': 1,
    'Binary String': 2,
    'CIDR Block': 3,
    'CVE': 4,
    'Email Address': 5,
    'Email Attachment': 6,
    'Email Subject': 7,
    'File Mapping': 8,
    'File Path': 9,
    'File name': 10,
    'FQDN': 11,
    'Fuzzy Hash': 12,
    'GOST Hash': 13,
    'Hash ION': 14,
    'IPv4 Address': 15,
    'IPv6 Address': 16,
    'MAC Address': 17,
    'MD5': 18,
    'Mutex': 19,
    'Password': 20,
    'Registry Key': 21,
    'Service Name': 22,
    'SHA-1': 23,
    'SHA-256': 24,
    'SHA-384': 25,
    'SHA-512': 26,
    'String': 27,
    'x509 Serial': 28,
    'x509 Subject': 29,
    'URL': 30,
    'URL Path': 31,
    'User-agent': 32,
    'Username': 33,
    'X-Mailer': 34,
}

OBJECT_TYPE_MAPPING = {
    'Adversary': 'adversaries',
    'Attack Pattern': 'attack_pattern',
    'Campaign': 'campaign',
    'Course of Action': 'course_of_action',
    'Event': 'events',
    'Exploit Target': 'exploit_target',
    'File': 'attachments',
    'Identity': 'identity',
    'Incident': 'incident',
    'Indicator': 'indicators',
    'Intrusion Set': 'intrusion_set',
    'Malware': 'malware',
    'Report': 'report',
    'Signature': 'signatures',
    'Task': 'tasks',
    'Tool': 'tool',
    'TTP': 'ttp',
    'Vulnerability': 'vulnerability',
}

STATUS_MAPPING = {
    'Active': 1,
    'Expired': 2,
    'Indirect': 3,
    'Review': 4,
    'Whitelisted': 5,
}

SCORE_MAPPING = {
    '0 - Very Low': 0,
    '1 - Very Low': 1,
    '2 - Very Low': 2,
    '3 - Very Low': 3,
    '4 - Very Low': 4,
    '5 - Low': 5,
    '6 - Low': 6,
    '7 - Medium': 7,
    '8 - Medium': 8,
    '9 - High': 9,
    '10 - Very High': 10
}