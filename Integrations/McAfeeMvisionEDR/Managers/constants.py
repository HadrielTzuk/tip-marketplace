INTEGRATION_NAME = u'McAfeeMvisionEDR'
DISMISS_THREAT_SCRIPT_NAME = u'{} - Dismiss Threat'.format(INTEGRATION_NAME)

TASK_IN_PROGRESS = u'IN_PROGRESS'
TASK_COMPLETED = u'COMPLETED'
TASK_FAILED = u'ERROR'

PAGE_LIMIT = 100
SUMMARY_TO_GET_THREAT_ID = u'Case generated by Threat'

# CONNECTORS
CONNECTOR_NAME = u'McAfee Mvision EDR - Threats Connector'
DEFAULT_TIME_FRAME = 0
DEFAULT_SEVERITY = u'Medium'
ACCEPTABLE_TIME_INTERVAL_IN_MINUTES = 5  # 5min
THREAT_ID_FIELD = u'threat_id'
WHITELIST_FILTER = u'whitelist'
BLACKLIST_FILTER = u'blacklist'
STORED_IDS_LIMIT = 3000

# MANAGERS
DEFAULT_SKIP = 0
PID_PROCESS = u"PID"
SHA256_PROCESS = u"SHA256"
NAME_PROCESS = u"Name"
PATH_PROCESS = u"Full Path"

# ACTIONS
PROVIDER_NAME = u"McAfeeMvisionEDR"
COMPLETED_STATUS = u"COMPLETED"
ERROR_STATUS = u"ERROR"
COMPLETED_ERROR_STATUS = u"COMPLETED_ERRORS"
IN_PROGRESS_STATUS = u"IN_PROGRESS"

GET_TOKEN_ENDPOINT = "https://iam.mcafee-cloud.com/iam/v1.0/token"
