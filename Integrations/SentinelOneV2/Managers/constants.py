INTEGRATION_NAME = 'SentinelOneV2'
PRODUCT_NAME = 'SentinelOne'

QUERY_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DEEP_VISIBILITY_QUERY_EVENTS_DEFAULT_LIMIT = 50
DEFAULT_BLACK_LIST_LIMIT = 50
MAX_BLACK_LIST_LIMIT = 1000
DEEP_VISIBILITY_QUERY_FINISHED = "FINISHED"
ENRICH_PREFIX = "SENO"
SENTINEL_PREFIX = 'SENO_'
THREAT_MITIGATED_STATUS = 'mitigated'
THREAT_TRUE_POSITIVE = 'true_positive'

COMPLETED_QUERY_STATUSES = ['FAILED', 'FINISHED', 'ERROR', 'QUERY_CANCELLED', 'TIMED_OUT']
FAILED_QUERY_STATUSES = ['FAILED', 'ERROR', 'QUERY_CANCELLED', 'TIMED_OUT']


# ACTIONS NAMES
PING_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Ping')
GET_SYSTEM_STATUS_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get System Status')
GET_SYSTEM_VERSION_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get System Version')
CREATE_HASH_BLACKLIST_RECORD_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Create Hash Blacklist Record')
CREATE_HASH_EXCLUSION_RECORD_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Create Hash Exclusion Record')
MITIGATE_THREAT_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Mitigate Threat')
DISCONNECT_AGENT_FROM_NETWORK_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Disconnect Agent From Network')
ENRICH_ENDPOINTS_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Enrich Endpoints')
RECONNECT_AGENT_TO_THE_NETWORK_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Reconnect Agent To The Network')
RESOLVE_THREAT_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Resolve Threat')
MARK_AS_THREAT_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Mark As Threat')
CREATE_PATH_EXCLUSION_RECORD_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Create Path Exclusion Record')
GET_THREATS_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get Threats')
INITIATE_FULL_SCAN_SCRIPT_NAME = "{} - {}".format(INTEGRATION_NAME, 'Initiate Full Scan')
INITIATE_DEEP_VISIBILITY_QUERY_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Initiate Deep Visibility Query')
MOVE_AGENTS_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Move Agents')
GET_APPLICATION_LIST_FOR_ENDPOINT_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get Applications List For Endpoints')
GET_AGENT_STATUS_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get Agent Status')
GET_BLACK_LIST_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get Blacklist')
GET_DEEP_VISIBILITY_QUERY_RESULT_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get Deep Visibility Query Result')
UPDATE_INCIDENT_STATUS_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Update Incident Status')
GET_GROUP_DETAILS_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get Group Details')
GET_HASH_REPUTATION_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get Hash Reputation')
GET_EVENTS_FOR_ENDPOINT_HOURS_BACK_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Get Events For Endpoint Hours Back')
DOWNLOAD_THREAT_FILE_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Download Threat File')
UPDATE_ANALYST_VERDICT_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Update Analyst Verdict')
ADD_THREAT_NOTE_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Add Threat Note')
REMOVE_HASH_BLACKLIST_RECORD_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'Delete Hash Blacklist Record')
LIST_SITES_SCRIPT_NAME = '{} - {}'.format(INTEGRATION_NAME, 'List Sites')

# TABLES NAMES
SYSTEM_VERSION_TABLE_NAME = 'System Version'
UNSUCCESSFUL_ATTEMPTS_TABLE_NAME = 'Unsuccessful Attempts'
AGENT_STATUSES_TABLE_NAME = 'Agents Statuses'
THREATS_TABLE_NAME = 'Sentinel One - Threats'
BLACKLIST_HASHES_TABLE_NAME = 'Blacklist Hashes'
SENTINEL_ONE_EVENTS_TABLE_NAME = 'SentinelOne Events'
SENTINEL_ONE_GROUPS_TABLE_NAME = 'SentinelOne Groups'
FOUND_EVENTS_TABLE_NAME = 'Found {} Events for {}'


MODE_MAPPER = {
    'Suppress Alerts': 'suppress',
    'Interoperability': 'disable_in_process_monitor',
    'Interoperability - Extended': 'disable_in_process_monitor_deep',
    'Performance Focus': 'disable_all_monitors',
    'Performance Focus - Extended': 'disable_all_monitors_deep'
}

ACTIVE_STATUS_VALUE = 'Active'
NOT_ACTIVE_STATUS_VALUE = 'Not Active'

KILL = 'kill'
QUARANTINE = 'quarantine'
UN_QUARANTINE = 'un-quarantine'
REMEDIATE = 'remediate'
ROLLBACK_REMEDIATION = 'rollback-remediation'

MITIGATION_MAPPING = {
    KILL: 'kill',
    QUARANTINE: 'quarantine',
    UN_QUARANTINE: 'un-quarantine',
    REMEDIATE: 'remediate',
    ROLLBACK_REMEDIATION: 'rollback-remediation'
}

AFFECTED_STATUS = 1
ACTIVITY_TYPE = 86

FALSE_POSITIVE = "False Positive"
TRUE_POSITIVE = "True Positive"
SUSPICIOUS = "Suspicious"
UNDEFINED = "Undefined"

ANALYST_VERDICT_MAPPING = {
    FALSE_POSITIVE: "false_positive",
    TRUE_POSITIVE: "true_positive",
    SUSPICIOUS: "suspicious",
    UNDEFINED: "undefined"
}

INCIDENT_STATUS_MAPPING = {
    'Unresolved': 'unresolved',
    'In Progress': 'in_progress',
    'Resolved': 'resolved'
}

SHA1_LENGTH = 40
DEFAULT_GET_BLACKLIST_ITEM_LIMIT = 1
FILTER_KEY_MAPPING = {
    "Select One": "",
    "Name": "name",
    "ID": "id"
}

FILTER_STRATEGY_MAPPING = {
    "Not Specified": "",
    "Equal": lambda item, value: str(item).lower() == str(value).lower(),
    "Contains": lambda item, value: str(value).lower() in str(item).lower()
}
