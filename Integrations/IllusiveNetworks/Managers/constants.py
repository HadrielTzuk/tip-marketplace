INTEGRATION_NAME = "IllusiveNetworks"
PRODUCT_NAME = "Illusive Networks"
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
RUN_FORENSIC_SCAN_ACTION = '{} - Run Forensic Scan'.format(INTEGRATION_NAME)
ENRICH_ENTITIES_ACTION = '{} - Enrich Entities'.format(INTEGRATION_NAME)
CONNECTOR_NAME = u'{} Detection Connector'.format(INTEGRATION_NAME)
LIST_DECEPTIVE_ITEMS_ACTION = '{} - List Deceptive Items'.format(INTEGRATION_NAME)
REMOVE_DECEPTIVE_SERVER_SCRIPT_NAME = '{} - Remove Deceptive Server'.format(INTEGRATION_NAME)
ADD_DECEPTIVE_SERVER_SCRIPT_NAME = '{} - Add Deceptive Server'.format(INTEGRATION_NAME)
ADD_DECEPTIVE_USER_SCRIPT_NAME = '{} - Add Deceptive User'.format(INTEGRATION_NAME)
REMOVE_DECEPTIVE_USER_SCRIPT_NAME = '{} - Remove Deceptive User'.format(INTEGRATION_NAME)

PING_QUERY = '{}/api/v1/incidents?limit=1'
ENRICH_ENTITIES_QUERY = "{}/api/v2/monitoring/hosts?host_names={}"
FORENSIC_SCAN_QUERY = "{}/api/v1/event/create-external-event?hostNameOrIp={}"
GET_INCIDENT_ID_QUERY = "{}/api/v1/incidents/id?event_id={}"
GET_FORENSIC_DATA_QUERY = "{}/api/v1GET_INCIDENT_ID_QUERY/forensics?event_id={}&type={}"
GET_DECEPTIVE_USERS_QUERY = "{}/api/v1/deceptive-entities/users?deceptive_user_type={}"
GET_DECEPTIVE_SERVERS_QUERY = "{}/api/v1/deceptive-entities/servers?deceptive_server_type={}"

CA_CERTIFICATE_FILE_PATH = "cacert.pem"
DEFAULT_ITEMS = 50
TIMEOUT_THRESHOLD = 0.9

FORENSIC_DATA_TYPES = {
    "include_sys_info":"HOST_INFO",
    "include_prefetch_files_info":"PREFETCH_INFO",
    "include_add_remove":"INSTALLED_PROGRAMS_INFO",
    "include_startup_info":"STARTUP_PROCESSES",
    "include_running_info":"RUNNING_PROCESSES",
    "include_user_assist_info":"USER_ASSIST_INFO",
    "include_powershell_info":"POWER_SHELL_HISTORY"
}

ILLUSIVE_NETWORKS_PREFIX = "ILLNET"

ALL = "All"
SUGGESTED = "Only Suggested"
APPROVED = "Only Approved"
ONLY_USERS = 'Only Users'
ONLY_SERVERS = 'Only Servers'

DECEPTIVE_STATE_MAPPING = {
    ALL: "ALL",
    SUGGESTED: "SUGGESTED",
    APPROVED: "APPROVED"
}

DECEPTIVE_USERS_TABLE_NAME = "Deceptive Users"
DECEPTIVE_SERVERS_TABLE_NAME = "Deceptive Servers"


DEFAULT_DEVICE_PRODUCT = "Illusive Networks"
DEFAULT_DEVICE_VENDOR = "Illusive Networks"

RATE_LIMIT_ERROR_IDENTIFIER = 'Rate limit error'


