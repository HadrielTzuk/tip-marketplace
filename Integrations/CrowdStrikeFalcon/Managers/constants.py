from enum import Enum
from SiemplifyDataModel import EntityTypes

INTEGRATION_NAME = "CrowdStrikeFalcon"
DEFAULT_DEVICE_VENDOR = "CrowdStrike"
PRODUCT_NAME = 'Crowdstrike Falcon'
VENDOR_NAME = 'Crowd Strike Falcon'
PROVIDER_NAME = "Crowd Strike Falcon"
SIEMPLIFY_PREFIX_FOR_APP = 'siemplify'

# ACTIONS NAMES
PING_SCRIPT_NAME = f"{INTEGRATION_NAME} - Ping"
UPDATE_DETECTION_SCRIPT_NAME = f"{INTEGRATION_NAME} - Update Detection"
CLOSE_DETECTION_SCRIPT_NAME = f"{INTEGRATION_NAME} - Close Detection"
LIST_HOSTS_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - List Hosts"
UPDATE_IOC_INFORMATION_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - Update IOC Information"
GET_HOSTS_BY_IOC_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - Get Hosts By IOC"
LIFT_CONTAINED_ENDPOINT_SCRIPT_NAME = f"{INTEGRATION_NAME} - Lift Contained Endpoint"
CONTAIN_ENDPOINT_SCRIPT_NAME = f"{INTEGRATION_NAME} - Contain Endpoint"
GET_HOST_INFORMATION_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - Get Host Information"
UPLOAD_IOCS_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - UploadIOCs"
ADD_COMMENT_TO_DETECTION_SCRIPT_NAME = f"{INTEGRATION_NAME} - Add Comment to Detection"
DELETE_IOC_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - Delete IOC"
LIST_UPLOADED_IOCS_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - List Uploaded IOCs"
GET_PROCESS_NAME_BY_IOC_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - Get Process By IOC"
LIST_HOST_VULNERABILITIES_SCRIPT_NAME = f"{DEFAULT_DEVICE_VENDOR} - List Host Vulnerabilities"
EXECUTE_COMMAND_SCRIPT_NAME = f"{INTEGRATION_NAME} - Execute Command"
DOWNLOAD_FILE_FROM_HOSTS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Download File"
GET_EVENT_OFFSET_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Event Offset"
UPDATE_IDENTITY_PROTECTION_DETECTION_SCRIPT_NAME = f"{INTEGRATION_NAME} - Update Identity Protection Detection"

# CONNECTOR NAMES
DETECTION_CONNECTOR_NAME = f"{PRODUCT_NAME} Detection Connector"
EVENT_STREAMING_CONNECTOR_NAME = f"{PROVIDER_NAME} Streaming Connector"
IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_NAME = f"{PROVIDER_NAME} Identity Protection Detections Connector"

DEFAULT_PADDING_PERIOD = 1
MAX_PADDING_PERIOD = 6

DEFAULT_SEVERITY = 3
DETECTION_EVENT_TYPE = 'DetectionSummaryEvent'
AUTH_ACTIVITY_AUDIT_EVENT_TYPE = 'AuthActivityAuditEvent'
USER_ACTIVITY_AUDIT_EVENT_TYPE = 'UserActivityAuditEvent'
REMOTE_RESPONSE_SESSION_START_EVENT_TYPE = 'RemoteResponseSessionStartEvent'
REMOTE_RESPONSE_SESSION_END_EVENT_TYPE = 'RemoteResponseSessionEndEvent'
SIEM_DETECTION_EVENT_TYPE = 'Detection'
SIEM_AUTH_ACTIVITY_AUDIT_EVENT_TYPE = 'AuthActivity'
SIEM_USER_ACTIVITY_AUDIT_EVENT_TYPE = 'UserActivity'
SIEM_REMOTE_RESPONSE_SESSION_EVENT_TYPE = 'Remote'
SIEM_UNKNOWN_EVENT_TYPE = 'Unknown'
STREAM_STARTED = 'streamStarted'
STREAM_STOPPED = 'streamStopped'
API_CLIENT_ID_KEY = 'APIClientID'
APP_ID_KEY = 'appId'
TIMEOUT_THRESHOLD = 0.9
DEFAULT_ALERT_NAME = "alert_with_no_behaviors"
DEFAULT_DEVICE_PRODUCT = "Falcon"
ENRICHMENT_PREFIX = 'CrowdStrike'
MAX_RESULTS_FOR_CONTAIN_LOGIC = 1000
SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

HOSTS = 'hostnames'
IP_ADDRESSES = 'ip_addresses'
URLS = 'urls'
HASHES = 'hashes'

# FILENAMES
OFFSET_FILE = 'offset.json'

# KEYS
OFFSET_DB_KEY = 'offset'
KEY_FOR_SAVED_OFFSET = 'offset'

# ACTION TYPES
ACTION_TYPE_DETECT = "Detect"
ACTION_TYPE_BLOCK = "Block"
ACTION_TYPE_MAPPING = {
    ACTION_TYPE_BLOCK: "Prevent",
    ACTION_TYPE_DETECT: "Detect"
}


class Severity(Enum):
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    UNKNOWN = 'UNKNOWN'


OPEN = 'open'
REOPEN = 'reopened'
SEVERITY_POSSIBLE_VALUES = [
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.UNKNOWN.value
]

API_ROOT_DEFAULT = "https://api.crowdstrike.com"


# TABLES NAMES
HOSTS_TABLE_NAME = 'Hosts'
HOSTS_BY_IOC = 'Devices Ran On - {}'
LIST_UPLOADED_IOCS = 'Custom IOCs'

# INSIGHTS CONSTANTS
INSIGHT_KEYS = {
    EntityTypes.ADDRESS: 'IP',
    EntityTypes.HOSTNAME: 'Hostname'
}

INSIGHT_VALUES = {
    EntityTypes.ADDRESS: 'local_ip',
    EntityTypes.HOSTNAME: 'hostname'
}


class DetectionStatusEnum(Enum):
    NEW = 'new'
    IN_PROGRESS = 'in_progress'
    TRUE_POSITIVE = 'true_positive'
    FALSE_POSITIVE = 'false_positive'
    IGNORED = 'ignored'
    SELECT_ONE = 'Select One'
    CLOSED = "closed"


class FilterStrategy(Enum):
    Equal = 'Equal'
    Contains = 'Contains'


FILTER_STRATEGY_MAPPING = {
    FilterStrategy.Equal.value: lambda item, value: str(item).lower() == str(value).lower(),
    FilterStrategy.Contains.value: lambda item, value: str(value).lower() in str(item).lower()
}

ADDRESS = 'ipv4'
DOMAIN = 'domain'

TYPES_IOC_MAPPER = {
    EntityTypes.HOSTNAME: DOMAIN,
    EntityTypes.ADDRESS: ADDRESS,
    EntityTypes.URL: DOMAIN,
    EntityTypes.FILEHASH: '',
}
SUPPORTED_HASH_TYPES = ['md5', 'sha256']

class DeviceStatusEnum(Enum):
    NORMAL = 'normal'
    CONTAINMENT_PENDING = 'containment_pending'
    CONTAINED = 'contained'
    LIFT_CONTAINMENT_PENDING = 'lift_containment_pending'


IOC_DEFAULT_SEVERITY = "high"


IOC_PLATFORM_VALUES = ["Windows", "Linux", "Mac"]

STATUS_NORMAL = "normal"
STATE_ONLINE = "online"

PLACEHOLDER_START = "["
PLACEHOLDER_END = "]"
CHARACTERS_LIMIT = 256

DEFAULT_MAX_LIMIT = 100

IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_SEVERITY = "0"
IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_MAX_HOURS_BACKWARDS = 1
IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEFAULT_LIMIT = 10

IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_PREFIX = "Crowdstrike_IDP"
IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEVICE_VENDOR = "Crowdstrike"
IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_DEVICE_PRODUCT = "Identity Protection"

IDENTITY_PROTECTION_DETECTIONS_CONNECTOR_SEVERITY_MAPPING = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
    "info": 0,
    "informational": 0,
}

SEVERITY_MAP = {
    "INFO": -1,
    "LOW": 40,
    "MEDIUM": 60,
    "HIGH": 80,
    "CRITICAL": 100
}

DATE_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'

DETECTION_STATUS_MAPPING = {
    "Select One": "",
    "Closed": "Closed",
    "In Progress": "In_progress",
    "New": "new",
    "Reopened": "reopened",
}

UNASSIGN = "Unassign"
