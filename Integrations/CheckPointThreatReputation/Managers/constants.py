INTEGRATION_NAME = 'CheckPointThreatReputation'
INTEGRATION_DISPLAY_NAME = 'CheckPoint Threat Reputation'

# Actions name
PING_SCRIPT_NAME = '{} - Ping'.format(INTEGRATION_NAME)
GET_HOST_REPUTATION_SCRIPT_NAME = '{} - Get HOST reputation'.format(INTEGRATION_NAME)
GET_IP_REPUTATION_SCRIPT_NAME = '{} - Get IP reputation'.format(INTEGRATION_NAME)
GET_FILE_HASH_REPUTATION_SCRIPT_NAME = '{} - GET File Hash reputation'.format(INTEGRATION_NAME)

ENTITY_ENRICHMENT_PREFIX = "CPThreatRep"
ENTITY_TABLE_NAME = "CheckPoint Threat Reputation"

WHITE_LIST_CLASSIFICATION = ("Benign", "Unclassified")
