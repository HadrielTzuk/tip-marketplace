PROVIDER_NAME = "VirusTotal"
INTEGRATION_NAME = "VirusTotalV3"

# ACTION NAMES
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_NAME)
ENRICH_IP_SCRIPT_NAME = "{} - Enrich IP".format(INTEGRATION_NAME)
ENRICH_HASH_SCRIPT_NAME = "{} - Enrich Hash".format(INTEGRATION_NAME)
GET_RELATED_URLS_SCRIPT_NAME = "{} - Get Related URLs".format(INTEGRATION_NAME)
GET_RELATED_DOMAINS_SCRIPT_NAME = "{} - Get Related Domains".format(INTEGRATION_NAME)
GET_RELATED_IPS_SCRIPT_NAME = "{} - Get Related URLs".format(INTEGRATION_NAME)
GET_RELATED_HASHES_SCRIPT_NAME = "{} - Get Related Hashes".format(INTEGRATION_NAME)
ENRICH_URL_SCRIPT_NAME = "{} - Enrich URL".format(INTEGRATION_NAME)
GET_DOMAIN_DETAILS_SCRIPT_NAME = "{} - Get Domain Details".format(INTEGRATION_NAME)
SEARCH_GRAPHS_SCRIPT_NAME = "{} - Search Graphs".format(INTEGRATION_NAME)
SEARCH_ENTITY_GRAPHS_SCRIPT_NAME = "{} - Search Entity Graphs".format(INTEGRATION_NAME)
GET_GRAPH_DETAILS_SCRIPT_NAME = "{} - Get Graph Details".format(INTEGRATION_NAME)
SUBMIT_FILE_SCRIPT_NAME = "{} - Submit File".format(INTEGRATION_NAME)
DOWNLOAD_FILE_SCRIPT_NAME = "{} - Download File".format(INTEGRATION_NAME)
ENRICH_IOC_SCRIPT_NAME = "{} - Enrich IOC".format(INTEGRATION_NAME)
ADD_VOTE_TO_ENTITY_SCRIPT_NAME = "Add Vote To Entity"
ADD_COMMENT_TO_ENTITY_SCRIPT_NAME  = "Add Comment To Entity"

CASE_WALL_LINK = "https://www.virustotal.com/gui/{entity_type}/{entity}/detection"
EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
DOMAIN_REGEX = r"[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+"

# DEFAULTS
DEFAULT_COMMENTS_COUNT = 50
PER_PAGE_ITEMS_COUNT = 40
DEFAULT_RELATED_ITEMS_COUNT = 100
MAX_COUNT_OF_GRAPHS = 10
DEFAULT_RELATED_URLS_LIMIT = 40
DEFAULT_RELATED_IPS_LIMIT = 40
DEFAULT_RELATED_HASHES_LIMIT = 40
DEFAULT_RELATED_DOMAINS_LIMIT = 40
DEFAULT_LIMIT = 10
DEFAULT_SANDBOX = "VirusTotal Jujubox"

# analyses statuses
COMPLETED = "completed"
QUEUED = "queued"
IN_PROGRESS = "in-progress"

# ADDITIONAL ENTITY TYPES
EMAIL_TYPE = 101
DOMAIN_TYPE = 102

DATA_ENRICHMENT_PREFIX = "VT3"
COMMENTS_TABLE_TITLE = 'Comments: {}'
REPORT_LINK_TITLE = 'Report Link: '
SIGMA_ANALYSIS_TITLE = "Sigma Analysis: {}"
GRAPHS_TABLE_TITLE = "Graph {} Links"
INSIGHT_TITLE = "Report: {}"

MD5_LENGTH = 32
SHA1_LENGTH = 40
SHA256_LENGTH = 64

IGNORED_CATEGORIES = ["confirmed-timeout", "type-unsupported", "timeout", "failure"]

RELATED_RESULTS_TYPE = {
    "combined": "Combined",
    "per_entity": "Per Entity"
}

IOC_TYPES = {
    "filehash": "Filehash",
    "url": "URL",
    "domain": "Domain",
    "ip_address": "IP Address",
}
IOC_LINK_ITEMS_MAPPING = {
    IOC_TYPES.get("filehash"): "file",
    IOC_TYPES.get("url"): "url",
    IOC_TYPES.get("domain"): "domain",
    IOC_TYPES.get("ip_address"): "ip-address"
}

IOC_LINK_STRUCTURE = "https://www.virustotal.com/gui/{ioc_type}/{ioc}/detection"
DEFAULT_RESUBMIT_DAYS = 30

# Connector
CONNECTOR_NAME = "{} - Livehunt Notifications Connector".format(INTEGRATION_NAME)
DEFAULT_TIME_FRAME = 1
DEFAULT_NOTIFICATIONS_LIMIT = 40
DEVICE_VENDOR = "VirusTotal"
DEVICE_PRODUCT = "VirusTotal"
TIMESTAMP_KEY = "notification_date"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
FALLBACK_NAME = "VT Livehunt Notification"

WIDGET_LIGHT_THEME_COLORS = {
    "fg1": "4f5064",
    "bg1": "ffffff",
    "bg2": "f4f5fa",
    "bd1": "d2d7e9"
}

WIDGET_DARK_THEME_COLORS = {
    "fg1": "b2b2b8",
    "bg1": "1b1b22",
    "bg2": "1f1f29",
    "bd1": "303045"
}

WIDGET_THEME_MAPPING = {
    "Light": WIDGET_LIGHT_THEME_COLORS,
    "Dark": WIDGET_DARK_THEME_COLORS
}

ERROR_RESPONSE_TEXTS = {
    "api_key_error": "Wrong API key",
    "permission_error": "not authorized to perform the requested operation",
}
