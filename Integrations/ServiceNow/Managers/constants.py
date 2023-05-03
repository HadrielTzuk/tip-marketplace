INTEGRATION_NAME = "ServiceNow"
PRODUCT_NAME = VENDOR = "Service Now"

# ACTION NAMES
ADD_ATTACHMENT_SCRIPT_NAME = '{} - Add Attachment'.format(INTEGRATION_NAME)
ADD_COMMENT_SCRIPT_NAME = '{} - Add Comment'.format(INTEGRATION_NAME)
ADD_COMMENT_AND_WAIT_FOR_REPLY_SCRIPT_NAME = '{} - Add Comment And Wait For Reply'.format(INTEGRATION_NAME)
CLOSE_INCIDENT_SCRIPT_NAME = '{} - Close Incident'.format(INTEGRATION_NAME)
CREATE_ALERT_INCIDENT_SCRIPT_NAME = '{} - Create Alert Incident'.format(INTEGRATION_NAME)
CREATE_INCIDENT_SCRIPT_NAME = '{} - Create Incident'.format(INTEGRATION_NAME)
CREATE_RECORD_SCRIPT_NAME = '{} - Create Record'.format(INTEGRATION_NAME)
GET_CMDB_RECORDS_SCRIPT_NAME = '{} - Get CMDB Records Details'.format(INTEGRATION_NAME)
GET_INCIDENT_SCRIPT_NAME = '{} - Get Incident'.format(INTEGRATION_NAME)
LIST_CMDB_RECORDS_SCRIPT_NAME = '{} - List CMDB Records'.format(INTEGRATION_NAME)
PING_SCRIPT_NAME = '{} - Ping'.format(INTEGRATION_NAME)
UPDATE_INCIDENT_SCRIPT_NAME = '{} - Update Incident'.format(INTEGRATION_NAME)
UPDATE_RECORD_SCRIPT_NAME = '{} - Update Record'.format(INTEGRATION_NAME)
WAIT_FOR_FIELD_UPDATE_SCRIPT_NAME = '{} - Wait For Field Update'.format(INTEGRATION_NAME)
WAIT_FOR_STATUS_UPDATE_SCRIPT_NAME = '{} - Wait For Status Update'.format(INTEGRATION_NAME)
DOWNLOAD_ATTACHMENTS_SCRIPT_NAME = '{} - Download Attachments'.format(INTEGRATION_NAME)
GET_RECORD_DETAILS_SCRIPT_NAME = '{} - Get Record Details'.format(INTEGRATION_NAME)
LIST_RECORDS_RELATED_TO_USER_SCRIPT_NAME = '{} - List Records Related To User'.format(INTEGRATION_NAME)
GET_USER_DETAILS_SCRIPT_NAME = '{} - Get User Details'.format(INTEGRATION_NAME)
GET_CHILD_INCIDENT_DETAILS_SCRIPT_NAME = '{} - Get Child Incident Details'.format(INTEGRATION_NAME)
GET_OAUTH_TOKEN_SCRIPT_NAME = '{} - Get Oauth Token'.format(INTEGRATION_NAME)
ADD_COMMENT_TO_RECORD_SCRIPT_NAME = '{} - Add Comment To Record'.format(INTEGRATION_NAME)
WAIT_FOR_COMMENTS_SCRIPT_NAME = '{} - Wait For Comments'.format(INTEGRATION_NAME)
LIST_RECORD_COMMENTS_SCRIPT_NAME = '{} - List Record Comments'.format(INTEGRATION_NAME)

# JOB NAMES
SYNC_CLOSURE = 'ServiceNow - SyncClosure'
SYNC_COMMENTS = 'ServiceNow - SyncComments'
SYNC_COMMENTS_BY_TAG = 'ServiceNow - SyncTableRecordCommentsByTag'

# CONNECTOR NAMES
CONNECTOR_NAME = "ServiceNowConnector"

# CONNECTOR PARAMS
DEFAULT_DAYS_BACKWARDS = 2
MAX_INCIDENTS_PER_CYCLE = 10
DEFAULT_NAME = 'ServiceNow'
MSG_ID_ERROR_MSG = "Can't get incident id"
NO_RESULTS = 'No Record found'
SN_DEFAULT_DOMAIN = 'global'
DEFAULT_EVENT_NAME = "ServiceNowEvent"
LINK_KEY = "link"

HIGH_PRIORITY = 80
MEDIUM_PRIORITY = 60
LOW_PRIORITY = 40
# In ServiceNow 1=high, 2=medium, 3=low
PRIORITY_MAPPING = {'1': HIGH_PRIORITY,
                    '2': MEDIUM_PRIORITY,
                    '3': LOW_PRIORITY}

# STATUSES
RESOLVED = "resolved"
CLOSED = "closed"
CANCELED = "canceled"
STATES = {
    'new': 1,
    'in progress': 2,
    'on hold': 3,
    'resolved': 6,
    'closed': 7,
    'canceled': 8
}
STATES_NAMES = {
    STATES[RESOLVED]: 'Resolved',
    STATES[CLOSED]: 'Closed',
    STATES[CANCELED]: 'Cancelled',
}

# FILENAMES
CSV_FILE_NAME = 'Relations.csv'
USERS_CVS_FILE_NAME = 'User Details'
CHILD_INCIDENTS_TABLE_NAME = 'Child Incident Details'

# CASE OPTIONS
CASE_RULE_GENERATOR = 'Service Now System'

INCIDENT_NUMBER_PREFIX = 'INC'
PROBLEM_NUMBER_PREFIX = 'PRB'

DEFAULT_MAX_RECORDS_TO_RETURN = 50
DEFAULT_MAX_DAYS_TO_RETURN = 1

RECORD_COMMENT_TYPES = {
    "Comment": "comments",
    "Work Note": "work_notes",
}

RECORD_COMMENT_TYPE_NAMES = {
    "Comment": "comments",
    "Work Note": "work notes",
}

SERVICE_NOW_TAG = 'ServiceNow {table_name}'
RECORDS_TAG = 'ServiceNow SysID:'
TAG_SEPARATOR = ":"
CASE_STATUS_CLOSED = 2
CASE_STATUS_OPEN = 1
SIEMPLIFY_COMMENT_PREFIX = 'Siemplify: '
SN_COMMENT_PREFIX = '{}: '.format(INTEGRATION_NAME)

GLOBAL_TIMEOUT_THRESHOLD_IN_MIN = 1
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
