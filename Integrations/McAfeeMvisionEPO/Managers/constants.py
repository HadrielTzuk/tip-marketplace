INTEGRATION_NAME = 'McAfeeMvisionEPO'
INTEGRATION_DISPLAY_NAME = 'McAfee Mvision ePO'

IAM_URL = 'https://iam.mcafee-cloud.com/iam/v1.2/token'
AUTH_PAYLOAD = {
    'grant_type': 'client_credentials',
    'audience': 'mcafee',
    'scope': 'epo.device.r epo.device.w epo.grps.r epo.grps.w epo.sftw.r epo.tags.r epo.tags.w',
}

HEADERS = {"Content-Type": "application/json"}

PING_SCRIPT_NAME = '{} - Ping'.format(INTEGRATION_NAME)
ADD_TAG_SCRIPT_NAME = '{} - Add Tag'.format(INTEGRATION_NAME)
REMOVE_TAG_SCRIPT_NAME = '{} - Remove Tag'.format(INTEGRATION_NAME)
ENRICH_ENDPOINT_SCRIPT_NAME = '{} - Enrich Endpoint'.format(INTEGRATION_NAME)
ENRICHMENT_PREFIX = 'MMV_EPO'
LIST_GROUPS_SCRIPT_NAME = '{} - List Groups'.format(INTEGRATION_NAME)
LIST_TAGS_SCRIPT_NAME = '{} - List Tags'.format(INTEGRATION_NAME)
LIST_ENDPOINTS_SCRIPT_NAME = '{} - List Endpoints In Group'.format(INTEGRATION_NAME)
PER_PAGE_LIMIT = 100
DEFAULT_LIMIT_GROUPS = 100
DEFAULT_LIMIT_ENDPOINTS = 100
DEFAULT_LIMIT_TAGS = 100