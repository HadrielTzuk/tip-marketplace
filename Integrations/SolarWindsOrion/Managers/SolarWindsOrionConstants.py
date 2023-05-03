PROVIDER_NAME = 'SolarWinds Orion'

# ACTIONS
PING_SCRIPT_NAME = '{} - Ping'.format(PROVIDER_NAME)
EXECUTE_QUERY_SCRIPT_NAME = '{} - Execute Query'.format(PROVIDER_NAME)
EXECUTE_ENTITY_QUERY_SCRIPT_NAME = '{} - Execute Entity Query'.format(PROVIDER_NAME)
ENRICH_ENDPOINT_SCRIPT_NAME = '{} - EnrichEndpoint'.format(PROVIDER_NAME)

ENDPOINTS = {
    'test_connectivity': '/SolarWinds/InformationService/v3/Json/Query'
}

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

DEFAULT_RESULTS_LIMIT = 100
BAD_REQUEST_STATUS_CODE = 400
DEFAULT_IP_KEY = 'IpAddress'
DEFAULT_HOSTNAME_KEY = 'Hostname'
DEFAULT_DISPLAY_NAME_KEY = 'DisplayName'
ENRICHMENT_PREFIX = 'SLRW_ORION'
ENRICHMENT_QUERY = 'SELECT IpAddress, DisplayName, NodeDescription, ObjectSubType,Description,SysName, Caption,DNS,' \
                   'Contact,Status,StatusDescription,IOSImage,IOSVersion,GroupStatus,LastBoot,SystemUpTime,' \
                   'AvgResponseTime,CPULoad,PercentMemoryUsed,MemoryAvailable,Severity,Category,EntityType, IsServer, ' \
                   'IsOrionServer FROM Orion.Nodes '
