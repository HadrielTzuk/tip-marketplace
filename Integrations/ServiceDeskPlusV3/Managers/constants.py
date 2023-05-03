INTEGRATION_NAME = "ServiceDeskPlusV3"
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
ADD_NOTE_ACTION = '{} - Add Note'.format(INTEGRATION_NAME)
ADD_NOTE_AND_WAIT_ACTION = '{} - Add Note And Wait For Reply'.format(INTEGRATION_NAME)
CLOSE_REQUEST_ACTION = '{} - Close Request'.format(INTEGRATION_NAME)
CREATE_REQUEST_ALERT_ACTION = '{} - Create Alert Request'.format(INTEGRATION_NAME)
CREATE_REQUEST_ACTION = '{} - Create Request'.format(INTEGRATION_NAME)
CREATE_REQUEST_DROPDOWN_ACTION = '{} - Create Request - Dropdown Lists'.format(INTEGRATION_NAME)
UPDATE_REQUEST_ACTION = '{} - Update Request'.format(INTEGRATION_NAME)
GET_REQUEST_ACTION = '{} - Get Request'.format(INTEGRATION_NAME)
WAIT_FOR_STATUS_UPDATE_ACTION = '{} - Wait For Status Update'.format(INTEGRATION_NAME)
WAIT_FOR_FIELD_UPDATE_ACTION = '{} - Wait For Field Update'.format(INTEGRATION_NAME)

UPDATE_REQUEST_TYPE = "UPDATE"
CREATE_REQUEST_TYPE = "CREATE"


#Requests
REQUESTS_URL = "requests"
SPECIFIC_REQUEST_URL = "requests/{}"
ADD_NOTE_URL = "requests/{}/notes"
CLOSE_REQUEST_URL = "requests/{}/close"
GET_NOTE_URL = "requests/{}/notes/{}"

#Jobs
SYNC_CLOSURE_SCRIPT_NAME = '{} - SyncClosure'.format(INTEGRATION_NAME)
SERVICE_DESK_PLUS_TAG = 'ServiceDeskPlus'
REQUESTS_TAG = 'ServiceDeskPlus Requests:'
TAG_SEPARATOR = ":"
CANCELLED_STATUS = 'Cancelled'
CLOSED_STATUS = 'Closed'
RESOLVED_STATUS = 'Resolved'
REASON = 'Maintenance'
ROOT_CAUSE = 'None'
COMMENT = '{status} in ServiceDeskPlus'
CASE_STATUS_CLOSED = 2
CASE_STATUS_OPEN = 1
DEFAULT_HOURS_BACKWARDS = 24
MIN_HOURS_BACKWARDS = 1
