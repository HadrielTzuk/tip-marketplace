INTEGRATION_NAME = "Phishrod"
INTEGRATION_DISPLAY_NAME = "Phishrod"

DEFAULT_DEVICE_VENDOR = "PhishRod"
DEFAULT_DEVICE_PRODUCT = "PhishRod"
DEFAULT_RULE_GENERATOR = "PhishRod"
DEFAULT_SOURCE_GROUPING_IDENTIFIER = "PhishRod"

# Actions
PING_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Ping"

# Connector Names
INCIDENTS_CONNECTOR_NAME = f"{INTEGRATION_NAME} - Incidents Connector"

# Connector Constant
TIMEOUT_THRESHOLD = 0.9
STORED_IDS_LIMIT = 2000

ENDPOINTS = {
    "ping": "/api/jsonws/phishrod.psc_secondary_analysis_tracking/get-secondary-analysis-tracking?apiKey={api_key}&clientId={client_id}",
    "get_incidents": "/api/jsonws/phishrod.psc_primary_analysis_tracking/get-primary-analysis-tracking?apiKey={api_key}&clientId={client_id}",
}

SEVERITIES = {"INFORMATIONAL": -1, "LOW": 40, "MEDIUM": 60, "HIGH": 80, "CRITICAL": 100}

FORBIDDEN_STATUS = 403
