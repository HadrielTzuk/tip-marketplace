INTEGRATION_NAME = "Google Security Command Center"
INTEGRATION_DISPLAY_NAME = "Google Security Command Center"

# Actions
PING_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Ping"
GET_FINDING_DETAILS_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Get Finding Details"
LIST_ASSET_VULNERABILITIES_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - List Asset Vulnerabilities"
ENRICH_ASSETS_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Enrich Assets"
UPDATE_FINDING_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Update Finding"

ENDPOINTS = {
    "ping": "v1/{type}/{id}/assets?pageSize=1",
    "get_finding_details": 'v1/{type}/{id}/sources/-/findings?pageSize=100&filter='
                           'name="{finding_name}"&orderBy=eventTime',
    "get_vulnerabilities": 'v1/{type}/{id}/sources/-/findings?filter=state="Active" AND '
                           'findingClass="Vulnerability" AND mute="UNMUTED" {time_filter}AND '
                           'resource.name="{resource_name}"&orderBy=eventTime desc',
    "get_misconfigurations": 'v1/{type}/{id}/sources/-/findings?filter=state="Active" {time_filter}'
                             'AND findingClass="Misconfiguration" AND '
                             'resource.name="{resource_name}"&orderBy=eventTime desc',
    "get_asset_details": "v1/{type}/{id}/assets?pageSize={page_size}&filter={filter}",
    "change_mute_status": 'v1/{finding_name}:setMute',
    "change_state_status": 'v1/{finding_name}:setState',
    "get_alerts": 'v1/{type}/{id}/sources/-/findings?filter=(state="ACTIVE" AND mute!="MUTED") AND '
                  '{finding_class_filter}{category_filter}AND '
                  '{severity_filter} AND {event_time_filter}&orderBy=eventTime&pageSize={page_size}'
}

SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
]
GOOGLE_SERVICE_ACCOUNT_VALUE = "google.iam.ServiceAccount"
GOOGLE_COMPUTE_ADDRESS_VALUE = "google.compute.Address"
GOOGLE_COMPUTE_INSTANCE_VALUE = "google.compute.Instance"
GOOGLE_CLOUD_STORAGE_VALUE = "google.cloud.storage.Bucket"


SUCCESS_STATUSES = ["200"]
ENRICHMENT_PREFIX = "GSCC"

ONLY_DATA = "Data"
ONLY_STATISTICS = "Statistics"
EVENTS_AND_STATISTICS = "Events + Statistics"
ONLY_VULNERABILTIES = "Vulnerabilities"
ONLY_MISCONFIGURATIONS = "Misconfigurations"
VULNERABILTIES_AND_MISCONFIGURATIONS = "Vulnerabilities + Misconfigurations"
DEFAULT_RECORDS_LIMIT = 50
VULNERABILITY_CLASS = "VULNERABILITY"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

TIMEFRAME_MAPPING = {
    "Last Week": "last_week",
    "Last Month": "last_month",
    "Last Year": "last_year",
    "All Time": "all_time"
}

STATISTICS_DICT = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "severity_unspecified": 0
}

MUTE_MAPPING = {
    "Mute": "MUTED",
    "Unmute": "UNMUTED",
    "Select One": None
}

STATE_MAPPING = {
    "Active": "ACTIVE",
    "Inactive": "INACTIVE",
    "Select One": None
}

SEVERITY_MAPPING = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 60,
    "LOW": 40,
    "SEVERITY_UNSPECIFIED": -1
}

DEFAULT_PRODUCT_FIELD_NAME = "findingClass"
DEFAULT_EVENT_FIELD_NAME = "category"
DEFAULT_MAX_HOURS_BACKWARDS = 1
DEFAULT_MAX_FINDINGS_TO_FETCH = 100

WHITELIST_FILTER = 'whitelist'
BLACKLIST_FILTER = 'blacklist'

DEFAULT_SEVERITY = "MEDIUM"

POSSIBLE_SEVERITIES = [
    "LOW", "MEDIUM", "HIGH", "CRITICAL"
]
SEVERITY_FILTER_MAPPING = {
    "LOW": '(severity="LOW" OR severity="MEDIUM" OR severity="HIGH" OR severity="CRITICAL" OR severity="SEVERITY_UNSPECIFIED")',
    "MEDIUM": '(severity="MEDIUM" OR severity="HIGH" OR severity="CRITICAL" OR severity="SEVERITY_UNSPECIFIED")',
    "HIGH": '(severity="HIGH" OR severity="CRITICAL" OR severity="SEVERITY_UNSPECIFIED")',
    "CRITICAL": '(severity="CRITICAL" OR severity="SEVERITY_UNSPECIFIED")',
    "SEVERITY_UNSPECIFIED": '(severity="LOW" OR severity="MEDIUM" OR severity="HIGH" OR severity="CRITICAL" OR severity="SEVERITY_UNSPECIFIED")',
}
POSSIBLE_FINDING_CLASS_FILTERS = [
    "Threat", "Vulnerability", "Misconfiguration", "SCC_Error", "Observation"
]