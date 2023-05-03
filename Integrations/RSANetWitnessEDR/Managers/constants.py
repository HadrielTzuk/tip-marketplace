INTEGRATION_NAME = "RSANetWitnessEDR"
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
ADDIPTOBLOCKLIST_ACTION = '{} - Add IP To Blacklist'.format(INTEGRATION_NAME)
ADDURLTOBLOCKLIST_ACTION = '{} - Add URL To Blacklist'.format(INTEGRATION_NAME)
ENRICHENDPOINT_ACTION = '{} - Enrich Endpoint'.format(INTEGRATION_NAME)
GET_IOC_DETAILS_ACTION = '{} - Get IOC Details'.format(INTEGRATION_NAME)

# Headers.
REQUEST_HEADERS = {"Accept": "application/json"}
#UI_SESSION_HEADERS = {"NetWitness-Token": "", "Content-Type": "application/x-www-form-urlencoded"}

#Endpoints
PING_QUERY = 'api/v2/health'
ADD_IP_TO_BLOCKLIST = 'api/v2/blacklist/ip?format=json'
ADD_URL_TO_BLOCKLIST = 'api/v2/blacklist/domain?format=json'
GET_ENDPOINT_IP_GUID = 'api/v2/machines?IpAddress={}&format=json'
GET_ENDPOINT_HOSTNAME_GUID = 'api/v2/machines?MachineName={}&format=json'
GET_ENDPOINT_DETAILS = 'api/v2/machines/{}?format=json'
GET_ENDPOINT_IOCS = 'api/v2/machines/{}/instantiocs?per_page={}&format=json'
GET_IOC_DETAIL = 'api/v2/instantiocs/{}?format=json'

ENRICHMENT_PREFIX = "RSA_EDR"

IOC_LEVEL_THRESHOLD = {
    'Low': 3,
    'Medium': 2,
    'High': 1,
    'Critical': 0
}
