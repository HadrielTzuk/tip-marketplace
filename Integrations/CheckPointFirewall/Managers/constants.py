INTEGRATION_NAME = "CheckPointFirewall"

# ACTIONS
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_NAME)
ADD_A_SAM_RULE_SCRIPT_NAME = "{} - Add a SAM Rule".format(INTEGRATION_NAME)
REMOVE_SAM_RULE_SCRIPT_NAME = "{} - Remove SAM Rule".format(INTEGRATION_NAME)
ADD_IP_TO_GROUP_SCRIPT_NAME = "{} - Add Ip to Group".format(INTEGRATION_NAME)
ADD_URL_TO_GROUP_SCRIPT_NAME = "{} - Add Url to Group".format(INTEGRATION_NAME)
LIST_LAYERS_ON_SITE_SCRIPT_NAME = "{} - List Layers on Site".format(INTEGRATION_NAME)
LIST_POLICIES_ON_SITE_SCRIPT_NAME = "{} - List Policies on Site".format(INTEGRATION_NAME)
REMOVE_IP_FROM_GROUP_SCRIPT_NAME = "{} - Remove Ip From Group".format(INTEGRATION_NAME)
REMOVE_URL_FROM_GROUP_SCRIPT_NAME = "{} - Remove Url From Group".format(INTEGRATION_NAME)
RUN_SCRIPT_SCRIPT_NAME = "{} - Remove Url From Group".format(INTEGRATION_NAME)
SHOW_LOGS_SCRIPT_NAME = "{} - Show Logs".format(INTEGRATION_NAME)
DOWNLOAD_LOG_ATTACHMENT_SCRIPT_NAME = "{} - Download Log Attachment".format(INTEGRATION_NAME)

REMOVE_SAM_RULE_DEFAULT_MSG = "Siemplify-generated-script-remove-sam-rule"
# CSV FILE NAMES
ACCESS_CONTROL_LAYERS_CSV_NAME = "Access Control Layers"
THREAT_PREVENTION_CONTROL_LAYERS_CSV_NAME = "Threat Prevention Control Layers"
RESULTS_CSV_NAME = 'Results'

# ATTACHMENTS SIZE LIMIT
ATTACHMENT_SIZE_LIMIT_MB = 3
# DEFAULT DELIMITER
PARAMETERS_DEFAULT_DELIMITER = ","
PARAMETERS_NEW_LINE_DELIMITER = "\n"

# SLEEP CONSTANT
SLEEP_TIME = 5

TIME_FRAME_MAPPING = {
    "Today": 'today',
    "Yesterday": "yesterday",
    "Last Hour": "last-hour",
    "Last 24 Hours": "last-24-hours",
    "Last 30 Days": "last-30-days",
    "This Week": "this-week",
    "This Month": "this-month",
    "All Time": "all-time"
}

# Log type mapping
LOG_MAPPING = {
    "Log": "logs",
    "Audit": "audit"
}

# ERROR_CODES
NOT_FOUND_CODE = 404
INVALID_PARAMETERS_CODE = 400
