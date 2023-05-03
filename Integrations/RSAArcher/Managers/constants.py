INTEGRATION_NAME = u"RSAArcher"

# Connector
CONNECTOR_NAME = "RSA Archer - Security Incidents Connector"
DEVICE_VENDOR = "RSA"
DEVICE_PRODUCT = "RSA Archer"
WHITELIST_FILTER = "whitelist"
BLACKLIST_FILTER = "blacklist"
DEFAULT_TIME_FRAME = 0
UNIX_FORMAT = 1
DATETIME_FORMAT = 2
DEFAULT_LIMIT = 50

PROVIDER_NAME = u"RSAArcher"
ADD_JOURNAL_ENTRY_SCRIPT_NAME = u'RSAArcher - AddIncidentJournalEntry'
DATE_CREATED_FIELD_NAME = "Date_Created"
SECURITY_INCIDENTS_APP_NAME = "Security Incidents"
SECURITY_ALERT = "Security_Alert"
SECURITY_EVENT = "Security_Event"

PRIORITY_MAP = {
    "P-0": 100,
    "P-1": 80,
    "P-2": 60,
    "P-3": 40
}

# Job
SYNC_SECURITY_INCIDENTS_SCRIPT_NAME = '{} - Sync Security Incidents'.format(INTEGRATION_NAME)
SYNC_SECURITY_INCIDENTS_JSON = 'sync_security_incidents.json'
SECURITY_INCIDENTS_FIELD = "security_incidents"
SYNC_FIELDS = "sync_fields"

INCIDENT_JOURNAL_TAG = u"Incident_Journal"
JOURNAL_ENTRY_TAG = u"Journal_Entry"
SECURITY_INCIDENT_TAG = u"Security_Incident"
SECURITY_INCIDENTS_LEVEL_TAG = u"Security_Incidents"