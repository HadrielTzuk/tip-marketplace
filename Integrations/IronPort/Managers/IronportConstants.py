from SiemplifyDataModel import EntityTypes

INTEGRATION_NAME = 'IronPort'
INTEGRATION_PREFIX = 'IP_'
SCRIPT_GET_ALL_RECIPIENTS_BY_SUBJECT = '{} - Get All Recipients By Subject'.format(INTEGRATION_NAME)
SCRIPT_PING = '{} - Ping'.format(INTEGRATION_NAME)
SCRIPT_GET_ALL_RECIPIENTS_BY_SENDER = '{} - Get All Recipients By Sender'.format(INTEGRATION_NAME)
SCRIPT_ADD_SENDER_TO_BLOCK_LIST = '{} - Add Sender To Block List'.format(INTEGRATION_NAME)
SCRIPT_GET_REPORT = '{} - Get Report'.format(INTEGRATION_NAME)

# API supports only 00 seconds and 000 microseconds
API_TIME_FORMAT = '%Y-%m-%dT%H:%M:00.000Z'
# API reports supports only 00 minutes 00 seconds and 000 microseconds
API_TIME_HOURS_FORMAT = '%Y-%m-%dT%H:00:00.000Z'
PRINT_TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'

DEVICE_TYPE = 'esa'
QUERY_TYPE = 'export'

MESSAGES_LIMIT = 100
DEFAULT_MESSAGES_PAGE_SIZE = 100
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100
DEFAULT_MAX_RECIPIENTS_TO_RETURN = 20

ENTITY_TYPES_MAPPING = {
    EntityTypes.USER: {
        'field': 'user',
        'report_types': [
            'mail_users_detail'
        ]
    },
    EntityTypes.ADDRESS: {
        'field': 'ip',
        'report_types': [
            'mail_sender_ip_hostname_detail',
            'mail_incoming_ip_hostname_detail'
        ]
    },
    EntityTypes.HOSTNAME: {
        'field': 'hostname',
        'report_types': [
            'mail_sender_ip_hostname_detail',
            'mail_incoming_ip_hostname_detail'
        ]
    },
}

CA_CERTIFICATE_FILE_PATH = "cacert.pem"
DAYS = "Days"
HOURS = "Hours"

ASYNC_RUN_TIMEOUT_MS = 5 * 60 * 1000
ITERATION_DURATION_BUFFER = 2 * 60 * 1000
EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"