INTEGRATION_NAME = "Snowflake"
INTEGRATION_DISPLAY_NAME = "Snowflake"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_CUSTOM_QUERY_SCRIPT_NAME = "{} - Execute Custom Query".format(INTEGRATION_DISPLAY_NAME)
EXECUTE_SIMPLE_QUERY_SCRIPT_NAME = "{} - Execute Simple Query".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping": "/api/statements?async=false",
    "submit_query": "/api/statements?async=true",
    "get_data": "/api/statements/{query_id}"
}

EXECUTION_FINISHED = 0
EXECUTION_IN_PROGRESS = 1
ALL_FIELDS_WILDCARD = "*"
ASC_SORT_ORDER = "ASC"

