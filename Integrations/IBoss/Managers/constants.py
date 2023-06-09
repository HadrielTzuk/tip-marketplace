INTEGRATION_NAME = 'iBoss'
INTEGRATION_DISPLAY_NAME = 'iBoss'

# Actions name
PING_SCRIPT_NAME = '{} - Ping'.format(INTEGRATION_NAME)
URLLOOKUP_SCRIPT_NAME = '{} - URLLookup'.format(INTEGRATION_NAME)
ADD_URL_TO_POLICY_BLOCK_LIST_SCRIPT_NAME = '{} - Add URL to Policy Block List'.format(INTEGRATION_NAME)
REMOVE_URL_FROM_POLICY_BLOCK_LIST_SCRIPT_NAME = '{} - Remove URL from Policy Block List'.format(INTEGRATION_NAME)
LIST_POLICY_BLOCK_LIST_ENTRIES_SCRIPT_NAME = '{} - List Policy Block List Entries'.format(INTEGRATION_NAME)
ADD_IP_TO_POLICY_BLOCK_LIST = '{} - Add IP to Policy Block List'.format(INTEGRATION_NAME)
REMOVE_IP_FROM_POLICY_BLOCK_LIST_SCRIPT_NAME = '{} - Remove IP from Policy Block List'.format(INTEGRATION_NAME)
URL_RECATEGORIZATION_SCRIPT_NAME = '{} - URL Recategorization'.format(INTEGRATION_NAME)

DIRECTION_MAPPER = {
    'Destination and Source': 0,
    'Source': 1,
    'Destination': 2,
}

ENRICHMENT_PREFIX="IBOSS"
POLICY_BLOCKED_ENRICHMENT_NAME = 'policy_blocked'