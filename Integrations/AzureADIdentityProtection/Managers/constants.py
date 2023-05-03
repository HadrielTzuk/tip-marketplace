INTEGRATION_NAME = "AzureADIdentityProtection"
INTEGRATION_DISPLAY_NAME = "Azure AD Identity Protection"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = "{} - Enrich Entities".format(INTEGRATION_DISPLAY_NAME)
UPDATE_USER_STATE_SCRIPT_NAME = "{} - Update User State".format(INTEGRATION_DISPLAY_NAME)

AUTH_URL = "https://login.microsoftonline.com/{}/oauth2/v2.0/token"
ENDPOINTS = {
    "ping": "/v1.0/identityProtection/riskDetections?top=1",
    "get_alerts": "/v1.0/identityProtection/riskDetections",
    "get_users": "/v1.0/identityProtection/riskyUsers/",
    "compromise": "/v1.0/identityProtection/riskyUsers/confirmCompromised",
    "dismiss": "/v1.0/identityProtection/riskyUsers/dismiss"
}

PRINCIPAL_NAME = "userPrincipalName"
DISPLAY_NAME = "userDisplayName"
RISK_COLOR_MAP = {
    "No Risk": "#339966",
    "Low": "#ffff00",
    "Medium": "#ff9900",
    "High": "#ff0000"
}
COMPROMISED_STATE = "Compromised"

# Connector
CONNECTOR_NAME = "{} - Risk Detections Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 100
DEVICE_VENDOR = "Microsoft Azure"
DEVICE_PRODUCT = "Azure AD Identity Protection"
API_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RISK_DETECTION_ID_FIELD = "id"

SEVERITY_MAP = {
    "low": 40,
    "medium": 60,
    "high": 80
}

SEVERITIES = ['low', 'medium', 'high']
