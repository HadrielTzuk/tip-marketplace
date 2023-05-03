INTEGRATION_NAME = "Mimecast"
INTEGRATION_DISPLAY_NAME = "Mimecast"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
REJECT_MESSAGE_ACTION = '{} - Reject Message'.format(INTEGRATION_NAME)
RELEASE_MESSAGE_ACTION = '{} - Release Message'.format(INTEGRATION_NAME)
REPORT_MESSAGE_ACTION = '{} - Report Message'.format(INTEGRATION_NAME)
PERMIT_SENDER_ACTION = '{} - Permit Sender'.format(INTEGRATION_NAME)
BLOCK_SENDER_ACTION = '{} - Block Sender'.format(INTEGRATION_NAME)
ADVANCED_ARCHIVE_SEARCH_ACTION = '{} - Advanced Archive Search'.format(INTEGRATION_NAME)
SIMPLE_ARCHIVE_SEARCH_ACTION = '{} - Simple Archive Search'.format(INTEGRATION_NAME)

ENDPOINTS = {
    "ping": "/api/account/get-account",
    "email_search": "/api/message-finder/search",
    "get_email_details": "/api/message-finder/get-message-info",
    'release_message': '/api/message-finder/release-held-email-to-sandbox',
    'release_message_sandbox': '/api/message-finder/release-held-email-to-sandbox',
    'report_message': '/api/message-finder/report-message',
    'reject_message': '/api/message-finder/reject-held-email',
    'manage_sender': '/api/managedsender/permit-or-block-sender',
    'execute_query': '/api/archive/search'
}

REPORT_TYPES = {
    "Malware": "malware",
    "Spam": "spam",
    "Phishing": "phishing"
}

SELECT_ONE_REASON = "select_one"

REJECTION_REASONS = {
    "Inappropriate Communication": "inappropriate_communication",
    "Confidential Information": "confidential_information",
    "Restricted Content": "disapproves_of_content",
    "Against Email Policy": "against_email_policies",
    "Select One": "select_one"
}

HEADERS = {
        'Authorization': None,
        'x-mc-app-id': None,
        'x-mc-date': None,
        'x-mc-req-id': None,
        'Content-Type': 'application/json'
    }

# Connector
CONNECTOR_NAME = "{} - Message Tracking Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_MAX_LIMIT = 100
DEVICE_VENDOR = "Mimecast"
DEVICE_PRODUCT = "Mimecast"
DEFAULT_RULE_GEN = "Mimecast Email"

FILTER_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

SEVERITY_MAP = {
    "negligible": -1,
    "low": 40,
    "medium": 60,
    "high": 80
}

SEVERITIES = ['negligible', 'low', 'medium', 'high']
POSSIBLE_STATUSES = ["delivery", "held", "accepted", "bounced", "deferred", "rejected", "archived"]
POSSIBLE_ROUTES = ["internal", "outbound", "inbound"]

DEFAULT_LIMIT = 50

TIMEFRAME_MAPPING = {
    "Last Hour": {"hours": 1},
    "Last 6 Hours": {"hours": 6},
    "Last 24 Hours": {"hours": 24},
    "Last Week": "last_week",
    "Last Month": "last_month",
    "Custom": "custom"
}
ALERT_ID_KEY = "message_id"
