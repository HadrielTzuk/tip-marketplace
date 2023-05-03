INTEGRATION_NAME = "CofenseTriage"
PRODUCT = "Cofense Triage"
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
ENRICH_URL_ACTION = '{} - Enrich URL'.format(INTEGRATION_NAME)
GET_DOMAIN_DETAILS_ACTION = '{} - Get Domain Details'.format(INTEGRATION_NAME)
GET_THREAT_INDICATOR_DETAILS_ACTION = '{} - Get Threat Indicator Details'.format(INTEGRATION_NAME)
DOWNLOAD_REPORT_EMAIL_ACTION = '{} - Download Report Email'.format(INTEGRATION_NAME)
DOWNLOAD_REPORT_PREVIEW_ACTION = '{} - Download Report Preview'.format(INTEGRATION_NAME)
GET_REPORT_HEADERS_ACTION = '{} - Get Report Headers'.format(INTEGRATION_NAME)
ADD_TAGS_TO_REPORT_ACTION = '{} - Add Tags To Report'.format(INTEGRATION_NAME)
CATEGORIZE_REPORT_ACTION = '{} - Categorize Report'.format(INTEGRATION_NAME)
LIST_CATEGORIES_ACTION = '{} - List Categories'.format(INTEGRATION_NAME)
GET_REPORT_RULES_ACTION = '{} - Get Report Rules'.format(INTEGRATION_NAME)
GET_REPORT_REPORTERS_ACTION = '{} - Get Report Reporters'.format(INTEGRATION_NAME)
LIST_REPORTS_RELATED_TO_THREAT_IND_ACTION = '{} - List Reports Related To Threat Indicators '.format(INTEGRATION_NAME)
LIST_PLAYBOOKS_ACTION = '{} - List Playbooks'.format(INTEGRATION_NAME)
EXECUTE_PLAYBOOK_ACTION = '{} - Execute Playbook'.format(INTEGRATION_NAME)

TOKEN_PAYLOAD = {"client_id": None,
                 "client_secret": None,
                 "grant_type": "client_credentials"
                 }

ACCESS_TOKEN_URL = '{}/oauth/token'
PING_QUERY = '{}/api/public/v2/system/status'
ENRICH_URL = '{}/api/public/v2/urls?filter[url]={}'
DOMAIN_URL = '{}/api/public/v2/hostnames?filter[hostname]={}'
THREAT_INDICATOR_URL = '{}/api/public/v2/threat_indicators?filter[threat_value]={}'
REPORTERS_URL = '{}/api/public/v2/reports/{}/reporter'
RULES_URL = '{}/api/public/v2/reports/{}/rules'
HEADERS_URL = '{}/api/public/v2/reports/{}/headers?page[size]={}'
CATEGORIES_URL = '{}/api/public/v2/categories'
REPORT_TAGS = '{}/api/public/v2/reports/{}?fields[reports]=tags'
REPORTS_URL = '{}/api/public/v2/reports/{}'
CATEGORY_URL = '{}/api/public/v2/categories?filter[name]={}'
CATEGORIZE_REPORT_URL = '{}/api/public/v2/reports/{}/categorize'
DOWNLOAD_URL = '{}/api/public/v2/reports/{}/download'
DOWNLOAD_PNG_URL = '{}/api/public/v2/reports/{}/download.png'
DOWNLOAD_JPG_URL = '{}/api/public/v2/reports/{}/download.jpg'
REPORTS = 'api/public/v2/reports'
REPORT_URLS = 'api/public/v2/reports/{report_id}/urls'
REPORT_HOSTNAMES = 'api/public/v2/reports/{report_id}/hostnames'
REPORT_THREAT_INDICATORS = 'api/public/v2/reports/{report_id}/threat_indicators'
REPORT_ATTACHMENT = 'api/public/v2/reports/{report_id}/attachments'
ATTACHMENT_PAYLOADS = 'api/public/v2/attachment_payloads'
REPORT_COMMENTS_URL = 'api/public/v2/reports/{report_id}/comments'
REPORT_HEADERS_URL = 'api/public/v2/reports/{report_id}/headers'
GET_THREAT_INDICATOR_IDS_URL = 'api/public/v2/threat_indicators'
GET_RELATED_REPORTS_URL = '/api/public/v2/threat_indicators/{threat_id}/reports?fields[reports]=location,risk_score,from_address,subject,received_at,reported_at,raw_headers,md5,sha256,match_priority,tags,categorization_tags,processed_at,created_at,updated_at&page[size]=200'
LIST_PLAYBOOKS_URL = 'api/public/v2/playbooks'
EXECUTE_PLAYBOOK_URL = 'api/public/v2/playbook_executions'

CONFENSE_TRIAGE_PREFIX = "COFENSE_TRG"
DEFAULT_RECORDS_LIMIT = 50
DEFAULT_PAGE_SIZE = 200
DEFAULT_MAX_REPORTS_TO_RETURN = 100
MIN_THRESHOLD = 0
MAX_THRESHOLD = 100
DEFAULT_TRESHOLD = 50
THREAT_LEVELS = ["Malicious", "Suspicious"]
REPORT_FILE_NAME = "{}.eml"
PNG_FILE_NAME = "{}.png"
JPG_FILE_NAME = "{}.jpg"

PNG_FORMAT = "PNG"
JPG_FORMAT = "JPG"


# Connector
CONNECTOR_NAME = "Cofense Triage - Reports Connector"
DEVICE_VENDOR = "Cofense"
DEVICE_PRODUCT = "Cofense Triage"
WHITELIST_FILTER = "whitelist"
BLACKLIST_FILTER = "blacklist"
DEFAULT_TIME_FRAME = 0
UNIX_FORMAT = 1
DATETIME_FORMAT = 2
DEFAULT_LIMIT = 100
RELATED_ENTITIES_DEFAULT_LIMIT = 200
CONNECTOR_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
MIN_RISK_SCORE = 0
MAX_RISK_SCORE = 100
REPORT_REQUESTS_FIELDS = {
    "reports": "location,risk_score,from_address,subject,received_at,reported_at,raw_headers,text_body,html_body,md5,sha256,match_priority,tags,categorization_tags,processed_at,created_at,updated_at",
    "urls": "url,risk_score,created_at,updated_at",
    "hostnames": "hostname,risk_score,created_at,updated_at",
    "threat_indicators": "threat_level,threat_type,threat_value,threat_source,created_at,updated_at",
}

FILTER_KEY_MAPPING = {
    "Select One": "",
    "Name": "name",
    "Description": "description"
}

FILTER_STRATEGY_MAPPING = {
    "Not Specified": "",
    "Equal": "Equal",
    "Contains": "Contains"
}
EQUAL = "Equal"
