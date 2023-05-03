INTEGRATION_NAME = "F5BIGIPiControlAPI"
INTEGRATION_DISPLAY_NAME = "F5 BIG-IP"

# Actions
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_DISPLAY_NAME)
LIST_DATA_GROUPS_SCRIPT_NAME = "{} - List Data Groups".format(INTEGRATION_DISPLAY_NAME)
ADD_IP_TO_DATA_GROUP_SCRIPT_NAME = "{} - Add IP To Data Group".format(INTEGRATION_DISPLAY_NAME)
LIST_PORT_LISTS_SCRIPT_NAME = "{} - List Port Lists".format(INTEGRATION_DISPLAY_NAME)
ADD_PORT_TO_PORT_LIST_SCRIPT_NAME = "{} - Add Port To Port List".format(INTEGRATION_DISPLAY_NAME)
CREATE_PORT_LIST_NAME = "{} - Create Port List".format(INTEGRATION_DISPLAY_NAME)
REMOVE_PORT_FROM_PORT_LIST_SCRIPT_NAME = "{} - Remove Port From Port List".format(INTEGRATION_DISPLAY_NAME)
LIST_ADDRESS_LISTS_SCRIPT_NAME = "{} - List Address Lists".format(INTEGRATION_DISPLAY_NAME)
LIST_IRULES_SCRIPT_NAME = "{} - List iRules".format(INTEGRATION_DISPLAY_NAME)
CREATE_DATA_GROUP_NAME = "{} - Create Data Group".format(INTEGRATION_DISPLAY_NAME)
DELETE_DATA_GROUP_NAME = "{} - Delete Data Group".format(INTEGRATION_DISPLAY_NAME)
CREATE_IRULE_SCRIPT_NAME = "{} - Create iRule".format(INTEGRATION_DISPLAY_NAME)
DELETE_IRULE_SCRIPT_NAME = "{} - Delete iRule".format(INTEGRATION_DISPLAY_NAME)
UPDATE_IRULE_SCRIPT_NAME = "{} - Update iRule".format(INTEGRATION_DISPLAY_NAME)
CREATE_ADDRESS_LIST_NAME = "{} - Create Address List".format(INTEGRATION_DISPLAY_NAME)
DELETE_ADDRESS_LIST_NAME = "{} - Delete Address List".format(INTEGRATION_DISPLAY_NAME)
CREATE_PORT_LIST_NAME = "{} - Create Port List".format(INTEGRATION_DISPLAY_NAME)
DELETE_PORT_LIST_NAME = "{} - Delete Port List".format(INTEGRATION_DISPLAY_NAME)
ADD_IP_TO_ADDRESS_LIST_SCRIPT_NAME = "{} - Add IP To Address List".format(INTEGRATION_DISPLAY_NAME)
REMOVE_IP_FROM_ADDRESS_LIST_SCRIPT_NAME = "{} - Remove IP From Address List".format(INTEGRATION_DISPLAY_NAME)
REMOVE_IP_FROM_DATA_GROUP_SCRIPT_NAME = "{} - Remove IP From Data Group".format(INTEGRATION_DISPLAY_NAME)

ENDPOINTS = {
    "ping": "/mgmt/tm/security/firewall/port-list",
    "list_data_groups": "/mgmt/tm/ltm/data-group/internal",
    "data_group": "/mgmt/tm/ltm/data-group/internal/{group_name}",
    "list_port_lists": "/mgmt/tm/security/firewall/port-list",
    "port_list": "/mgmt/tm/security/firewall/port-list/{port_list_name}",
    "list_address_lists":"/mgmt/tm/security/firewall/address-list/",
    "address_list":"/mgmt/tm/security/firewall/address-list/{list_name}",
    "list_irules":"/mgmt/tm/ltm/rule/",
    "create_data_group":"/mgmt/tm/ltm/data-group/internal",
    "delete_data_group":"/mgmt/tm/ltm/data-group/internal/{group_name}",
    "create_irule": "/mgmt/tm/ltm/rule",
    "delete_irule": "/mgmt/tm/ltm/rule/{name}",
    "update_irule": "/mgmt/tm/ltm/rule/{name}",
    "create_address_list": "/mgmt/tm/security/firewall/address-list/",
    "delete_address_list": "/mgmt/tm/security/firewall/address-list/{list_name}",
    "create_port_list": "/mgmt/tm/security/firewall/port-list"
}

GROUP_TYPES = {
    "IP Address":"ip",
    "String":"string",
    "Integer":"integer"
}

DEFAULT_LIMIT = 50
EQUAL_FILTER = "Equal"
CONTAINS_FILTER = "Contains"
IP_GROUP_TYPE = "ip"
IPV4_MASK = "/32"
IPV6_MASK = "/128"
ALL_IPV6 = "::"

