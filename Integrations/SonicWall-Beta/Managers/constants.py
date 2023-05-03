INTEGRATION_NAME = u'SonicWall-Beta'

PING_SCRIPT_NAME = u'{} - Ping'.format(INTEGRATION_NAME)
ADD_IP_SCRIPT_NAME = u'{} - Add IP to Address Group'.format(INTEGRATION_NAME)
REMOVE_IP_SCRIPT_NAME = u'{} - Remove IP from Address Group'.format(INTEGRATION_NAME)
ADD_URL_SCRIPT_NAME = u'{} - Add URL to URI List'.format(INTEGRATION_NAME)
LIST_ADDRESS_GROUPS_SCRIPT_NAME = u'{} - List Address Groups'.format(INTEGRATION_NAME)
ADD_URI_TO_GROUP_SCRIPT_NAME = u'{} - Add URI List to URI Group'.format(INTEGRATION_NAME)
REMOVE_URL_SCRIPT_NAME = u'{} - Remove URL from URI List'.format(INTEGRATION_NAME)
LIST_URI_LISTS_SCRIPT_NAME = u'{} - List URI Lists'.format(INTEGRATION_NAME)
LIST_URI_GROUPS_SCRIPT_NAME = u'{} - List URI Groups'.format(INTEGRATION_NAME)
CREATE_CFS_SCRIPT_NAME = u'{} - Create CFS Profile'.format(INTEGRATION_NAME)

ENDPOINTS = {
    u'auth': u'api/sonicos/auth',
    u'ping': u'api/sonicos/user/status/all',
    u'address_groups': u'/api/sonicos/address-groups/{ip_type}/name/{group_name}',
    u'create_address': u'/api/sonicos/address-objects/{ip_type}',
    u'confirm': u'/api/sonicos/config/pending',
    u'all_addresses': u'/api/sonicos/address-objects/{ip_type}',
    u'add_url': u'/api/sonicos/content-filter/uri-list-objects/name/{uri_list}',
    u'get_address_groups': u'/api/sonicos/address-groups/{ip_type}',
    u'delete_url': u'/api/sonicos/content-filter/uri-list-objects',
    u'get_uri_lists': u'/api/sonicos/content-filter/uri-list-objects',
    u'add_uri_to_group': u'/api/sonicos/content-filter/uri-list-groups',
    u'list_groups': u'/api/sonicos/content-filter/uri-list-groups',
    u'create_cfs_profile': u'/api/sonicos/content-filter/profiles'
}

HEADERS = {
    u'Accept': u'application/json',
    u'Accept-Encoding': u'*/*',
    u'Content-Type': u'application/json'
}

NO_MATCH_ERROR_CODE = u'E_NO_MATCH'
UNAUTHORIZED_ERROR_CODE = u'E_UNAUTHORIZED'
NOT_FOUND_ERROR_CODE = u'E_NOT_FOUND'
GENERAL_ERROR_CODE = u'E_ERROR'

IPV4_TYPE_STRING = u'ipv4'
IPV6_TYPE_STRING = u'ipv6'
ALL_TYPE_STRING = u'all'
MAX_LIMIT = 100
ALLOWED_URI_FIRST_STRING = u'Allowed URI First'

