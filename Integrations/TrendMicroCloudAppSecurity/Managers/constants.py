INTEGRATION_NAME = "TrendMicroCloudAppSecurity"
DISPLAY_INTEGRATION_NAME = "Trend Micro Cloud App Security"
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
ADD_ENTITIES_TO_BLOCKLIST_ACTION = '{} - Add Entities To Blocklist'.format(INTEGRATION_NAME)
ENTITY_EMAIL_SEARCH_ACTION = '{} - Entity Email Search'.format(INTEGRATION_NAME)
MITIGATE_EMAILS_ACTION = '{} - Mitigate Emails'.format(INTEGRATION_NAME)
MITIGATE_ACCOUNTS_ACTIONS = '{} - Mitigate Accounts'.format(DISPLAY_INTEGRATION_NAME)
ENRICH_ENTITIES_ACTIONS = '{} - Enrich Entities'.format(DISPLAY_INTEGRATION_NAME)

PING_QUERY = '{}/v1/sweeping/mails?limit=1'
ADD_ENTITIES_TO_BLOCKLIST_QUERY = '{}/v1/remediation/mails'
MITIGATE_EMAILS_QUERY = '{}/v1/mitigation/mails'
GET_EMAILS = '{}/v1/sweeping/mails'
MITIGATE_ACCOUNTS_QUERY = '{}/v1/mitigation/accounts'
FETCH_MITIGATION_RESULTS_QUERY = '{}/v1/mitigation/accounts?batch_id={}'

SHA1_HASH_LENGTH = 40
SHA256_LENGTH = 64
EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

MITIGATE_EMAIL_ACTION_TYPES = {
    "Delete": "MAIL_DELETE",
    "Quarantine": "MAIL_QUARANTINE"
}

SERVICE_TYPES = {
    "Exchange": "exchange",
    "Gmail": "gmail"
}

ACCOUNT_PROVIDER_TYPES = {
    "exchange": "office365",
    "gmail": "google"  
}

MITIGATE_ACCOUNT_TYPES = {
    "Disable Account": "ACCOUNT_DISABLE",
    "Enable MFA": "ACCOUNT_ENABLE_MFA",
    "Reset Password": "ACCOUNT_RESET_PASSWORD",
    "Revoke Sign In Sessions": "ACCOUNT_REVOKE_SIGNIN_SESSIONS",     
}

MITIGATION_SUCCESS = "Success"
MITIGATION_IN_PROGRESS = "Executing"
MITIGATION_SKIPPED = "Skipped"
MITIGATION_FAILED = "Failed"

QUARANTINE_MITIGATION_ACTION = "Quarantine"
GMAIL_SERVICE = "Gmail"

MITIGATE_ACCOUNT_SERVICE = "exchange"
MITIGATE_ACCOUNT_PROVIDER = "office365"

MAX_DAYS_BACKWARDS = 90
DEFAULT_DAYS_BACKWARDS = 30
DEFAULT_NUMBER_OF_EMAILS = 100

ENRICHMENT_FIELD = {"TMCAS_blocked": "True"}
