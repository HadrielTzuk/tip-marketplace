PROVIDER_NAME = "RecordedFuture"
DEFAULT_DEVICE_VENDOR = "Recorded Future"

# Actions name
PING_SCRIPT_NAME = "Ping"
ENRICH_CVE_SCRIPT_NAME = "{} - Enrich CVE".format(PROVIDER_NAME)
ENRICH_HASH_SCRIPT_NAME = "{} - Enrich Hash".format(PROVIDER_NAME)
ENRICH_HOST_SCRIPT_NAME = "{} - Enrich Host".format(PROVIDER_NAME)
ENRICH_IP_SCRIPT_NAME = "{} - Enrich IP".format(PROVIDER_NAME)
ENRICH_URL_SCRIPT_NAME = "{} - Enrich URL".format(PROVIDER_NAME)
ENRICH_IOC_SCRIPT_NAME = "{} - Enrich IOC".format(PROVIDER_NAME)
GET_ALERT_DETAILS_SCRIPT_NAME = "{} - Get Alert Details".format(PROVIDER_NAME)
GET_CVE_RELATED_ENTITIES_SCRIPT_NAME = "{} - Get CVE Related Entities".format(PROVIDER_NAME)
GET_HASH_RELATED_ENTITIES_SCRIPT_NAME = "{} - Get Hash Related Entities".format(PROVIDER_NAME)
GET_HOST_RELATED_ENTITIES_SCRIPT_NAME = "{} - Get Host Related Entities".format(PROVIDER_NAME)
GET_IP_RELATED_ENTITIES_SCRIPT_NAME = "{} - Get Ip Related Entities".format(PROVIDER_NAME)
ADD_ANALYST_NOTE_SCRIPT_NAME = "{} - Add Analyst Note".format(PROVIDER_NAME)
UPDATE_ALERT_SCRIPT_NAME = "{} - Update Alert".format(PROVIDER_NAME)

# Connector
CONNECTOR_NAME = "Recorded Future - Security Alerts Connector"
DEFAULT_TIME_FRAME = 0
CONNECTOR_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
DEFAULT_LIMIT = 100
SEVERITY_MAP = {
    "Low": 40,
    "Medium": 60,
    "High": 80,
    'Critical': 100
}
STORED_IDS_LIMIT = 3000
ALERT_ID_FIELD = "id"

DEFAULT_THRESHOLD = 25
DEFAULT_SCORE = 0
SUPPORTED_ENTITY_TYPES_ENRICHMENT = ["URL", "ADDRESS", "FILEHASH", "CVE", "HOSTNAME"]
SUPPORTED_ENTITY_TYPES_RELATED_ENTITIES = ["ADDRESS", "FILEHASH", "CVE", "HOSTNAME"]
ENRICHMENT_DATA_PREFIX = "RF"

TOPIC_MAP = {
    "None": "",
    "Actor Profile": "TXSFt2",
    "Analyst On-Demand Report": "VlIhvH",
    "Cyber Threat Analysis": "TXSFt1",
    "Flash Report": "TXSFt0",
    "Indicator": "TXSFt4",
    "Informational": "UrMRnT",
    "Malware/Tool Profile": "UX0YlU",
    "Source Profile": "UZmDut",
    "Threat Lead": "TXSFt3",
    "Validated Intelligence Event": "TXSFt5",
    "Weekly Threat Landscape": "VlIhvG",
    "YARA Rule": "VTrvnW",
}

ALERT_STATUS_MAP = {
    "Unassigned":"unassigned",
    "Assigned":"assigned",
    "Pending":"pending",
    "Dismissed":"dismiss",
    "New":"no-action",
    "Resolved":"actionable",
    "Flag for Tuning":"tuning", 
    "Select One": None
}
