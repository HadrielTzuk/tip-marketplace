INTEGRATION_NAME = "Humio"
INTEGRATION_DISPLAY_NAME = "Humio"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_CUSTOM_SEARCH_SCRIPT_NAME = "{} - Execute Custom Search".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_SIMPLE_SEARCH_SCRIPT_NAME = "{} - Execute Simple Search".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping": "/api/v1/repositories/humio-audit/query",
    "get_events": "/api/v1/repositories/{repository_name}/query",
}

HEADERS = {
    "Accept": "application/json",
}

# Connector
CONNECTOR_NAME = "Humio - Events Connector"
DEFAULT_TIME_FRAME = 1
DEFAULT_LIMIT = 20
DEVICE_VENDOR = "Humio"
DEVICE_PRODUCT = "Humio"
DEFAULT_MAX_LIMIT = 100
DEFAULT_ALERT_NAME = "Humio Alert"
SEVERITY_DEFAULT_KEY = "Default"

TIMEFRAME_MAPPING = {
    "Last Hour": {"hours": 1},
    "Last 6 Hours": {"hours": 6},
    "Last 24 Hours": {"hours": 24},
    "Last Week": "last_week",
    "Last Month": "last_month",
    "Custom": "custom"
}

SORT_FIELD_TYPE_MAPPING = {
    "String": "string",
    "Number": "number",
    "Hex": "hex"
}

SORT_ORDER_MAPPING = {
    "ASC": "asc",
    "DESC": "desc"
}
