INTEGRATION_NAME = "AnyRun"
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
ANALYZE_URL_ACTION = '{} - Analyze URL'.format(INTEGRATION_NAME)
ANALYZE_FILE_ACTION = '{} - Analyze File'.format(INTEGRATION_NAME)
ANALYZE_FILEURL_ACTION = '{} - Analyze File URL'.format(INTEGRATION_NAME)
GET_REPORT_ACTION = '{} - Get Report'.format(INTEGRATION_NAME)
SEARCH_REPORT_HISTORY_ACTION = '{} - Search Report History'.format(INTEGRATION_NAME)


ANY_RUN_API_URL = "https://api.any.run/"

#Endpoints
PING_QUERY = 'v1/user/'
ANALYSIS_QUERY = 'v1/analysis'
ANALYSIS_URL_TASK = 'v1/analysis/{}'

#Mapping
NETWORK_STATUS_MAPPING = {
    'On': 'true',
    'Off': 'false'
}
NETWORK_PRIVACY_TYPE = {
    'By Link': 'bylink',
    'Public': 'public',
    'Owner':'owner'
}

STATUS_IN_PROGRESS = "in progress"
URL_ELEMENT = "URL"
FILE_ELEMENT = "FILE"
FILEURL_ELEMENT = "FileURL"

ENDPOINTS = {
    'analysis_history': 'v1/analysis/',
    'get_report': 'v1/analysis/{uuid}'
}

DEFAULT_THRESHOLD = 0
DEFAULT_SEARCH_LIMIT = 25
DEFAULT_SKIP_NUMBER = 0
SHA256_LENGTH = 64
MD5_LENGTH = 32
SHA1_LENGTH = 40
SLEEP_TIME = 2

