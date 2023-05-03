INTEGRATION_NAME = "Intsights"
VENDOR = "Intsights"

PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
CLOSE_ALERT_ACTION = '{} - Close Alert'.format(INTEGRATION_NAME)
ASSIGN_ALERT_ACTION = '{} - Assign Alert'.format(INTEGRATION_NAME)
ASK_AN_ANALYST_ACTION = '{} - Ask An Analyst'.format(INTEGRATION_NAME)
TAKEDOWN_REQUEST_ACTION = '{} - Takedown Request'.format(INTEGRATION_NAME)
REOPEN_ALERT_ACTION = '{} - Reopen Alert'.format(INTEGRATION_NAME)
GET_ALERT_IMAGE_ACTION = '{} - Get Alert Image'.format(INTEGRATION_NAME)
SUBMIT_REMEDIATION_EVIDENCE_ACTION = '{} - Submit Remediation Evidence'.format(INTEGRATION_NAME)
DOWNLOAD_ALERT_CSV_ACTION = '{} - Download Alert CSV'.format(INTEGRATION_NAME)
SEARCH_IOCS_ACTION = '{} - SearchIOCs'.format(INTEGRATION_NAME)
ADD_NOTE_ACTION = '{} - Add Note'.format(INTEGRATION_NAME)


CONNECTOR_SCRIPT_NAME = f'{INTEGRATION_NAME} - Connector'
ALERT_FIELD_ID = 'alert_id'

MAX_RATE = 5
MIN_RATE = 1

SUPPORTED_REMEDIATION_FILES_FORMATS = ["pdf", "jpeg", "txt", "png", "jpg"]

PRIORITIES = {
    'High': 80,
    'Medium': 60,
    'Low': 40
}

ACTION_TYPE_ALERT = "ALERT"
ACTION_TYPE_USER = "USER"

# Requests
ASSIGN_ALERT_URL = "{}/public/v1/data/alerts/assign-alert/{}"
TAKEDOWN_REQUEST_URL = "{}/public/v1/data/alerts/takedown-request/{}"
SUBMIT_REMEDIATION_EVIDENCE_URL = "{}/public/v1/data/alerts/upload-remediation-evidence/{}/{}/false"

REASON_MAPPING = {
    "Problem Solved": "ProblemSolved",
    "Informational Only": "InformationalOnly",
    "Problem We Are Aware Of": "ProblemWeAreAlreadyAwareOf",
    "Company Owned Domain": "CompanyOwnedDomain",
    "Legitimate Application/Profile": "LegitimateApplication/Profile",
    "Not Related To My Company": "NotRelatedToMyCompany",
    "False Positive": "FalsePositive",
    "Other": "Other"
}

SEVERITY_VALUES = ["Medium", "High"]
