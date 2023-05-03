API_URL = 'https://backstory.googleapis.com'
SCOPES = ["https://www.googleapis.com/auth/chronicle-backstory"]
API_LIMIT_ERROR = 429
MAX_RETRIES = 40
LIMIT = 50
DEFAULT_LIMIT = 100
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
MAX_LIMIT = 1000
MAX_EVENT_LIMIT = 10000
UDM_QUERY_EVENTS_DEFAULT_LIMIT = 50
UDM_QUERY_EVENTS_MAX_LIMIT = 200
MAX_HOURS_BACKWARDS = 1
NOW = "now"
INTEGRATION_NAME = "GoogleChronicle"
INTEGRATION_DISPLAY_NAME = "Google Chronicle"
EXECUTE_UDM_QUERY_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Execute UDM Query"

IOC_SEVERITIES = {
    "n/a": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4
}
WHITELIST_FILTER = 'whitelist'
BLACKLIST_FILTER = 'blacklist'
VENDOR = 'Google'
PRODUCT = 'Google Chronicle'

# Sync Data job
SYNC_DATA_SCRIPT_NAME = "Google Chronicle - Sync Data"
DEFAULT_HOURS_BACKWARDS = 24
DEFAULT_FETCH_INTERVAL = 12
MAX_FETCH_LIMIT_FOR_JOB = 1000
TYPE_DELIMITER = "__"
CHRONICLE_USER = "Chronicle SOAR"
JSON_REGEX_PATTERN = '{(?:[^{}]|(?R))*}'

PRIORITY_SIEMPLIFY_TO_CHRONICLE = {
    0: 100,
    2: 200,
    3: 300,
    4: 400,
    5: 500
}

STATUS_SIEMPLIFY_TO_CHRONICLE = {
    0: 4,   # open
    1: 3    # closed
}

REASON_SIEMPLIFY_TO_CHRONICLE = {
    0: 2,  # malicious
    1: 1,  # not malicious
    2: 3,  # maintenance
    4: 0  # unknown
}

SIEMPLIFY_REASON_TO_CHRONICLE_VERDICT = {
    0: 1,   # malicious -> True Positive
    1: 2,   # not malicious -> False Positive
    3: 0,   # maintenance -> Unspecified
    4: 0    # unknown -> Unspecified
}

SIEMPLIFY_USEFULNESS_TO_CHRONICLE_REPUTATION = {
    0: 0,   # None ->
    1: 2,   # Not Useful
    2: 1    # Useful
}

ENDPOINTS = {
    "batch_update": "/batch",
    "udm_search": "v1/events:udmSearch"
}

SIMILARITY_BY_NAME_AND_PRODUCT = "Alert Name, Alert Type and Product"
SIMILARITY_BY_NAME = "Alert Name and Alert Type"
SIMILARITY_BY_PRODUCT = "Product"
SIMILARITY_BY_ASSETS = "Only IOCs/Assets"


ONLY_EVENTS = "Only Events"
ONLY_STATISTICS = "Only Statistics"
EVENTS_AND_STATISTICS = "Events + Statistics"

EVENT_TYPES = ["EVENTTYPE_UNSPECIFIED", "PROCESS_UNCATEGORIZED", "PROCESS_LAUNCH", "PROCESS_INJECTION",
               "PROCESS_PRIVILEGE_ESCALATION", "PROCESS_TERMINATION", "PROCESS_OPEN", "PROCESS_MODULE_LOAD",
               "REGISTRY_UNCATEGORIZED", "REGISTRY_CREATION", "REGISTRY_MODIFICATION", "REGISTRY_DELETION",
               "SETTING_UNCATEGORIZED", "SETTING_CREATION", "SETTING_MODIFICATION", "SETTING_DELETION",
               "MUTEX_UNCATEGORIZED", "MUTEX_CREATION", "FILE_UNCATEGORIZED", "FILE_CREATION", "FILE_DELETION",
               "FILE_MODIFICATION", "FILE_READ", "FILE_COPY", "FILE_OPEN", "FILE_MOVE", "FILE_SYNC",
               "USER_UNCATEGORIZED", "USER_LOGIN", "USER_LOGOUT", "USER_CREATION", "USER_CHANGE_PASSWORD",
               "USER_CHANGE_PERMISSIONS", "USER_STATS", "USER_BADGE_IN", "USER_DELETION", "USER_RESOURCE_CREATION",
               "USER_RESOURCE_UPDATE_CONTENT", "USER_RESOURCE_UPDATE_PERMISSIONS", "USER_COMMUNICATION",
               "USER_RESOURCE_ACCESS", "USER_RESOURCE_DELETION", "GROUP_UNCATEGORIZED", "GROUP_CREATION",
               "GROUP_DELETION", "GROUP_MODIFICATION", "EMAIL_UNCATEGORIZED", "EMAIL_TRANSACTION", "EMAIL_URL_CLICK",
               "NETWORK_UNCATEGORIZED", "NETWORK_FLOW", "NETWORK_CONNECTION", "NETWORK_FTP", "NETWORK_DHCP",
               "NETWORK_DNS", "NETWORK_HTTP", "NETWORK_SMTP", "STATUS_UNCATEGORIZED", "STATUS_HEARTBEAT",
               "STATUS_STARTUP", "STATUS_SHUTDOWN", "STATUS_UPDATE", "SCAN_UNCATEGORIZED", "SCAN_FILE",
               "SCAN_PROCESS_BEHAVIORS", "SCAN_PROCESS", "SCAN_HOST", "SCAN_VULN_HOST", "SCAN_VULN_NETWORK",
               "SCAN_NETWORK", "SCHEDULED_TASK_UNCATEGORIZED", "SCHEDULED_TASK_CREATION", "SCHEDULED_TASK_DELETION",
               "SCHEDULED_TASK_ENABLE", "SCHEDULED_TASK_DISABLE", "SCHEDULED_TASK_MODIFICATION",
               "SYSTEM_AUDIT_LOG_UNCATEGORIZED", "SYSTEM_AUDIT_LOG_WIPE", "SERVICE_UNSPECIFIED", "SERVICE_CREATION",
               "SERVICE_DELETION", "SERVICE_START", "SERVICE_STOP", "SERVICE_MODIFICATION", "GENERIC_EVENT",
               "RESOURCE_CREATION", "RESOURCE_DELETION", "RESOURCE_PERMISSIONS_CHANGE", "RESOURCE_READ",
               "RESOURCE_WRITTEN", "ANALYST_UPDATE_VERDICT", "ANALYST_UPDATE_REPUTATION",
               "ANALYST_UPDATE_SEVERITY_SCORE", "ANALYST_UPDATE_STATUS", "ANALYST_ADD_COMMENT"]

TIMEFRAME_MAPPING = {
    "Last Hour": {"hours": 1},
    "Last 6 Hours": {"hours": 6},
    "Last 24 Hours": {"hours": 24},
    "Last Week": "last_week",
    "Last Month": "last_month",
    "Custom": "custom",
    "Alert Time Till Now": "Alert Time Till Now",
    "5 Minutes Around Alert Time": "5 Minutes Around Alert Time",
    "30 Minutes Around Alert Time": "30 Minutes Around Alert Time",
    "1 Hour Around Alert Time": "1 Hour Around Alert Time"
}

CONFIDENCE_TO_INT_MAPPING = {
    "high": 90,
    "medium": 60,
    "low": 30
}

INT_TO_SEVERITY_MAPPING = {
    0: "N/A",
    1: "Info",
    2: "Low",
    3: "Medium",
    4: "High"
}

RULE_ALERT_TYPE = "RULE"
EXTERNAL_ALERT_TYPE = "EXTERNAL"
IOC_ALERT_TYPE = "IOC"

HOURS_BACKWARDS_STRING = "Max Hours Backwards"
SHA256_LENGTH = 64
MD5_LENGTH = 32
SHA1_LENGTH = 40


class HashArtifactTypes:
    MD5 = "artifact.hash_md5"
    SHA1 = "artifact.hash_sha1"
    SHA256 = "artifact.hash_sha256"


NOT_ASSIGNED = "n/a"

# Unified Alerts Connector
UNIFIED_CONNECTOR_DEVICE_VENDOR = "Google Chronicle"
UNIFIED_CONNECTOR_DEVICE_PRODUCT = "Google Chronicle"
UNIFIED_CONNECTOR_CONNECTOR_NAME = "Google Chronicle - Chronicle Alerts Connector"
UNIFIED_CONNECTOR_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
UNIFIED_CONNECTOR_DEFAULT_LIMIT = 100
UNIFIED_CONNECTOR_DEFAULT_MAX_LIMIT = 50
UNIFIED_CONNECTOR_DEFAULT_TIME_FRAME = 1
UNIFIED_CONNECTOR_MAX_TIME_FRAME = 167
EXTERNAL_ALERT_ASSET_TYPE = "asset"
EXTERNAL_ALERT_USER_TYPE = "user"
DEFAULT_PADDING_PERIOD = 1
MAX_PADDING_PERIOD = 12
STRING_PREFIX_SEPARATOR = "_"

ALERT_TYPES = {
    "rule": "rule",
    "external": "external",
    "ioc": "ioc",
}

ALERT_TYPE_NAMES = {
    ALERT_TYPES.get("rule"): "RULE",
    ALERT_TYPES.get("external"): "EXTERNAL",
    ALERT_TYPES.get("ioc"): "IOC"
}

NESTED_KEYS_DELIMITER = ">"
EXTERNAL_MULTIPLE_VALUES_NESTED_KEYS = [
    "event>principal>ip",
    "event>principal>nat_ip",
    "event>principal>mac",
    "event>principal>asset>ip",
    "event>principal>asset>nat_ip",
    "event>principal>asset>mac",
    "event>src>ip",
    "event>src>nat_ip",
    "event>src>mac",
    "event>src>asset>ip",
    "event>src>asset>nat_ip",
    "event>src>asset>mac",
    "event>target>ip",
    "event>target>nat_ip",
    "event>target>mac",
    "event>target>asset>ip",
    "event>target>asset>nat_ip",
    "event>target>asset>mac",
    "event>intermediary>ip",
    "event>intermediary>nat_ip",
    "event>intermediary>mac",
    "event>intermediary>asset>ip",
    "event>intermediary>asset>nat_ip",
    "event>intermediary>asset>mac",
    "event>observer>ip",
    "event>observer>nat_ip",
    "event>observer>mac",
    "event>observer>asset>ip",
    "event>observer>asset>nat_ip",
    "event>observer>asset>mac",
    "event>about>ip",
    "event>about>nat_ip",
    "event>about>mac",
    "event>about>asset>ip",
    "event>about>asset>nat_ip",
    "event>about>asset>mac",
    "event>network>email>to",
    "event>principal>user>emailAddresses",
    "event>src>user>emailAddresses",
    "event>target>user>emailAddresses",
    "event>intermediary>user>emailAddresses",
    "event>observer>user>emailAddresses",
    "event>about>user>emailAddresses"
]

RULE_MULTIPLE_VALUES_NESTED_KEYS = [
    "event>principal>ip",
    "event>principal>nat_ip",
    "event>principal>mac",
    "event>principal>asset>ip",
    "event>principal>asset>nat_ip",
    "event>principal>asset>mac",
    "event>src>ip",
    "event>src>nat_ip",
    "event>src>mac",
    "event>src>asset>ip",
    "event>src>asset>nat_ip",
    "event>src>asset>mac",
    "event>target>ip",
    "event>target>nat_ip",
    "event>target>mac",
    "event>target>asset>ip",
    "event>target>asset>nat_ip",
    "event>target>asset>mac",
    "event>intermediary>ip",
    "event>intermediary>nat_ip",
    "event>intermediary>mac",
    "event>intermediary>asset>ip",
    "event>intermediary>asset>nat_ip",
    "event>intermediary>asset>mac",
    "event>observer>ip",
    "event>observer>nat_ip",
    "event>observer>mac",
    "event>observer>asset>ip",
    "event>observer>asset>nat_ip",
    "event>observer>asset>mac",
    "event>about>ip",
    "event>about>nat_ip",
    "event>about>mac",
    "event>about>asset>ip",
    "event>about>asset>nat_ip",
    "event>about>asset>mac",
    "event>network>email>to",
    "event>principal>user>emailAddresses",
    "event>src>user>emailAddresses",
    "event>target>user>emailAddresses",
    "event>intermediary>user>emailAddresses",
    "event>observer>user>emailAddresses",
    "event>about>user>emailAddresses"
]

SIEMPLIFY_SEVERITIES = {
    "info": -1,
    "low": 40,
    "medium": 60,
    "high": 80,
    "critical": 100,
    "informational": -1,
    "error": 40
}

GCTI_ALERT_SEVERITY_MAPPING = {
    "UNKNOWN_SEVERITY": -1,
    "INFORMATIONAL": -1,
    "ERROR": 40,
    "LOW": 40,
    "MEDIUM": 60,
    "HIGH": 80,
    "CRITICAL": 100
}

FALLBACK_SEVERITY_VALUES = ["info", "low", "medium", "high", "critical"]

FILTER_TYPE_DELIMITER = "."
FILTER_VALUES_DELIMITER = ","
FILTER_LOGIC = {
    "and": "and",
    "or": "or"
}
SUPPORTED_OPERATORS = [">=", "<=", "!=", "=", ">", "<"]
MULTIPLE_VALUES_SUPPORTED_OPERATORS = {
    "=": FILTER_LOGIC.get("or"),
    "!=": FILTER_LOGIC.get("and")
}

ALERT_TYPES_SUPPORTED_FILTERS = {
    ALERT_TYPES.get("rule"): {
        "severity": {
            "response_key": "siemplify_severity",
            "operators": ["=", "!=", ">", "<", ">=", "<="],
            "possible_values": ["low", "medium", "high", "critical", "informational", "error"],
            "values_mapping": SIEMPLIFY_SEVERITIES
        },
        "ruleName": {
            "response_key": "name",
            "operators": ["=", "!="],
            "possible_values": None
        },
        "ruleID": {
            "response_key": "rule_id",
            "operators": ["=", "!="],
            "possible_values": None
        },
        "alertState": {
            "response_key": "alert_state",
            "operators": ["=", "!="],
            "possible_values": ["alerting", "not alerting"]
        }
    },
    ALERT_TYPES.get("external"): {
        "productName": {
            "response_key": "product_name",
            "operators": ["=", "!="],
            "possible_values": None
        },
        "productEventType": {
            "response_key": "product_event_type",
            "operators": ["=", "!="],
            "possible_values": None
        },
        "threatName": {
            "response_key": "name",
            "operators": ["=", "!="],
            "possible_values": None
        },
        "severity": {
            "response_key": "unified_siemplify_severity",
            "operators": ["=", "!=", ">", "<", ">=", "<="],
            "possible_values": ["low", "medium", "high", "critical", "informational", "error"],
            "values_mapping": SIEMPLIFY_SEVERITIES
        },
        "type": {
            "response_key": "alert_type",
            "operators": ["=", "!="],
            "possible_values": ["asset", "user"]
        },
    },
    ALERT_TYPES.get("ioc"): {
        "rawSeverity": {
            "response_key": "highest_siemplify_severity",
            "operators": ["=", "!=", ">", "<", ">=", "<="],
            "possible_values": ["low", "medium", "high", "critical", "info"],
            "values_mapping": SIEMPLIFY_SEVERITIES
        },
        "intRawConfidenceScore": {
            "response_key": "average_confidence_score",
            "operators": ["=", "!=", ">", "<", ">=", "<="],
            "possible_values": [str(item) for item in range(101)],
            "transformer": int
        },
        "normalizedConfidenceScore": {
            "response_key": "average_normalized_confidence_score",
            "operators": ["=", "!=", ">", "<", ">=", "<="],
            "possible_values": ["low", "medium", "high", "critical"],
            "values_mapping": SIEMPLIFY_SEVERITIES
        }
    }
}

ENTITY_TYPES_MAPPING = {
    "DestinationURL": ["target.url"],
    "FILEHASH": {
        "MD5": ["target.file.md5"],
        "SHA1": ["target.file.sha1"],
        "SHA256": ["target.file.sha256"]
    },
    "ADDRESS": ["principal.ip", "principal.asset.ip", "src.ip", "src.asset.ip", "target.ip", "target.asset.ip"],
    "HOSTNAME": ["principal.hostname", "src.hostname", "target.hostname", "target.asset.hostname"],
    "PROCESS": {
        "INT": ["target.process.pid", "target.process.parent_pid", "target.process.parent_process.pid"],
        "STR": ["target.process.file.full_path", "target.process.parent_process.file.full_path"]
    },
    "EMAILSUBJECT": ["network.email.subject"],
    "USERUNIQNAME": {
        "EMAIL": ["network.email.from", "network.email.to", "network.email.cc", "network.email.bcc"],
        "USERNAME": ["principal.user.user_display_name", "src.user.user_display_name", "target.user.user_display_name"]
    }
}

ACTIVITY_TYPES_MAPPING = {
    "NETWORK": ["NETWORK_UNCATEGORIZED", "NETWORK_FLOW", "NETWORK_CONNECTION", "NETWORK_FTP", "NETWORK_DHCP",
                "NETWORK_DNS", "NETWORK_HTTP", "NETWORK_SMTP"],
    "USER": ["USER_UNCATEGORIZED", "USER_LOGIN", "USER_LOGOUT", "USER_CREATION", "USER_CHANGE_PASSWORD",
             "USER_CHANGE_PERMISSIONS", "USER_STATS", "USER_BADGE_IN", "USER_DELETION", "USER_RESOURCE_CREATION",
             "USER_RESOURCE_UPDATE_CONTENT", "USER_RESOURCE_UPDATE_PERMISSIONS", "USER_COMMUNICATION",
             "USER_RESOURCE_ACCESS", "USER_RESOURCE_DELETION"],
    "PROCESS": ["PROCESS_UNCATEGORIZED", "PROCESS_LAUNCH", "PROCESS_INJECTION", "PROCESS_PRIVILEGE_ESCALATION",
                "PROCESS_TERMINATION", "PROCESS_OPEN", "PROCESS_MODULE_LOAD"],
    "FILE": ["FILE_UNCATEGORIZED", "FILE_CREATION", "FILE_DELETION", "FILE_MODIFICATION", "FILE_READ", "FILE_COPY",
             "FILE_OPEN", "FILE_MOVE", "FILE_SYNC"],
    "REGISTRY": ["REGISTRY_UNCATEGORIZED", "REGISTRY_CREATION", "REGISTRY_MODIFICATION", "REGISTRY_DELETION"],
    "EMAIL": ["EMAIL_UNCATEGORIZED", "EMAIL_TRANSACTION", "EMAIL_URL_CLICK"],
    "GROUP": ["GROUP_UNCATEGORIZED", "GROUP_CREATION", "GROUP_DELETION", "GROUP_MODIFICATION"],
    "SETTING": ["SETTING_UNCATEGORIZED", "SETTING_CREATION", "SETTING_MODIFICATION", "SETTING_DELETION"],
    "MUTEX": ["MUTEX_UNCATEGORIZED", "MUTEX_CREATION"],
    "STATUS": ["STATUS_UNCATEGORIZED", "STATUS_HEARTBEAT", "STATUS_STARTUP", "STATUS_SHUTDOWN", "STATUS_UPDATE"],
    "SCAN": ["SCAN_UNCATEGORIZED", "SCAN_FILE", "SCAN_PROCESS_BEHAVIORS", "SCAN_PROCESS", "SCAN_HOST",
             "SCAN_VULN_HOST", "SCAN_VULN_NETWORK", "SCAN_NETWORK"],
    "SCHEDULED TASK": ["SCHEDULED_TASK_UNCATEGORIZED", "SCHEDULED_TASK_CREATION", "SCHEDULED_TASK_DELETION",
                       "SCHEDULED_TASK_ENABLE", "SCHEDULED_TASK_DISABLE", "SCHEDULED_TASK_MODIFICATION"],
    "SYSTEM AUDIT": ["SYSTEM_AUDIT_LOG_UNCATEGORIZED", "SYSTEM_AUDIT_LOG_WIPE"],
    "SERVICE": ["SERVICE_UNSPECIFIED", "SERVICE_CREATION", "SERVICE_DELETION", "SERVICE_START", "SERVICE_STOP",
                "SERVICE_MODIFICATION"],
    "RESOURCE": ["RESOURCE_CREATION", "RESOURCE_DELETION", "RESOURCE_PERMISSIONS_CHANGE", "RESOURCE_READ",
                 "RESOURCE_WRITTEN"],
    "ANALYST": ["ANALYST_UPDATE_VERDICT", "ANALYST_UPDATE_REPUTATION", "ANALYST_UPDATE_SEVERITY_SCORE",
                "ANALYST_UPDATE_STATUS", "ANALYST_ADD_COMMENT"],
    "ALL": []
}

RULE_ALERT_PREFIX = "GChronicle"

