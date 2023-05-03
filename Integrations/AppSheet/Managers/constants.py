INTEGRATION_NAME = "AppSheet"
INTEGRATION_DISPLAY_NAME = "AppSheet"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
ADD_RECORD_SCRIPT_NAME = "{} - Add Record".format(INTEGRATION_DISPLAY_NAME)
UPDATE_RECORD_SCRIPT_NAME = "{} - Update Record".format(INTEGRATION_DISPLAY_NAME)
DELETE_RECORD_SCRIPT_NAME = "{} - Delete Record".format(INTEGRATION_DISPLAY_NAME)
SEARCH_RECORDS_SCRIPT_NAME = "{} - Search Records".format(INTEGRATION_DISPLAY_NAME)
LIST_TABLES_SCRIPT_NAME = "{} - List Tables".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping":"/api/v2/apps/{app_id}/tables",
    "record_management": "/api/v2/apps/{app_id}/tables/{table_name}/Action",
    "list_tables": "/api/v2/apps/{app_id}/tables/"
}

SEARCH_RECORDS_TABLE_NAME = "Records"
LIST_TABLES_TABLE_NAME = "Available Tables"
DEFAULT_LIMIT = 50

EQUAL_FILTER = "Equal"
CONTAINS_FILTER = "Contains"
