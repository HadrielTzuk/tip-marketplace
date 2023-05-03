INTEGRATION_NAME = "Tenable.io"
INTEGRATION_DISPLAY_NAME = "Tenable.io"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
ENRICH_ENTITIES_SCRIPT_NAME = "{} - Enrich Entities".format(INTEGRATION_DISPLAY_NAME)
GET_VULNERABILITY_DETAILS_SCRIPT_NAME = "{} - Get Vulnerability Details".format(INTEGRATION_DISPLAY_NAME)
LIST_ENDPOINT_VULNERABILITIES_SCRIPT_NAME = "{} - List Endpoint Vulnerabilities".format(INTEGRATION_DISPLAY_NAME)
LIST_PLUGIN_FAMILIES_SCRIPT_NAME = "{} - List Plugin Families".format(INTEGRATION_DISPLAY_NAME)
LIST_POLICIES_SCRIPT_NAME = "{} - List Policies".format(INTEGRATION_DISPLAY_NAME)
SCAN_ENDPOINTS_SCRIPT_NAME = "{} - Scan Endpoints".format(INTEGRATION_DISPLAY_NAME)
LIST_SCANNERS_SCRIPT_NAME = "{} - List Scanners".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping": "/plugins/families?all=true",
    "assets": "/assets",
    "asset": "/assets/{id}",
    "list_plugin_families": "/plugins/families?all=true",
    "initiate_export": "/vulns/export",
    "get_export_status": "/vulns/export/{export_id}/status",
    "export_chunk_data": "/vulns/export/{export_id}/chunks/{chunk_id}",
    "get_vulnerabilities_details": "/workbenches/vulnerabilities/{plugin_id}/info",
    "list_vulnerabilities": "/workbenches/assets/{asset_id}/vulnerabilities?{query_string}",
    "list_policies": "/policies",
    "create_scan": "/scans",
    "launch_scan": "/scans/{scan_id}/launch",
    "check_scan_status": "/scans/{scan_id}/latest-status",
    "get_scan_results": "/scans/{scan_id}",
    "list_scanners": "/scanners"
}

ENRICHMENT_PREFIX = "TenableIO"
DELIMITER = ","

# Connector
CONNECTOR_NAME = "{} - Vulnerabilities Connector".format(INTEGRATION_DISPLAY_NAME)
DEFAULT_SEVERITY = "Medium"
DEVICE_VENDOR = "Tenable"
DEVICE_PRODUCT = "Tenable.io"
DEFAULT_TIME_FRAME = 30
DEFAULT_RULE_GEN = "Tenable.io Vulnerability"

BLACK_COLOR = "#000000"

SEVERITY_MAP = {
    "info": -1,
    "low": 40,
    "medium": 60,
    "high": 80,
    "critical": 100
}

SEVERITY_REVERSE_MAP = {
    0: "Info",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical"
}

SEVERITY_COLORS = {
    0: BLACK_COLOR,
    1: "#00ccff",
    2: "#ffcc00",
    3: "#ff9900",
    4: "#ff0000"
}

SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
POSSIBLE_STATUSES = ["open", "reopened", "fixed"]
DEFAULT_STATUS_FILTER = "open, reopened"
HOST_GROUPING = "Host"
VULNERABILITY_GROUPING = "Vulnerability"
NONE_GROUPING = "None"
POSSIBLE_GROUPINGS = [NONE_GROUPING, HOST_GROUPING, VULNERABILITY_GROUPING]
FINISHED_STATUS = "FINISHED"
CANCELLED_STATUS = "CANCELLED"
ERROR_STATUS = "ERROR"
DEFAULT_VULNERABILITIES_LIMIT = 50
MAX_VULNERABILITIES_LIMIT = 200
EQUAL_FILTER = "Equal"
CONTAINS_FILTER = "Contains"
DEFAULT_PLUGIN_FAMILIES_LIMIT = 50
DEFAULT_POLICIES_LIMIT = 50
MAX_POLICIES_LIMIT = 100

DEFAULT_TIMEOUT = 300

# Scan statuses
COMPLETED_SCAN = "completed"
ABORTED_SCAN = "aborted"
CANCELED_SCAN = "canceled"
PAUSED_SCAN = "paused"
STOPPED_SCAN = "stopped"
BAD_SCAN_STATUSES = [ABORTED_SCAN, CANCELED_SCAN, STOPPED_SCAN]
