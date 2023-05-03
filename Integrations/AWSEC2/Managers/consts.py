INTEGRATION_NAME = 'AWSEC2'
INTEGRATION_DISPLAY_NAME = "AWS EC2"
VALID_STATUS_CODES = (200, 204)

DEFAULT_MAX_RESULTS = 50
MAX_RESULTS_LIMIT = 1000

# Actions names:
PING = 'Ping'
START_INSTANCE = 'Start Instance'
STOP_INSTANCE = 'Stop Instance'
LIST_INSTANCES = 'List Instances'
LIST_SECURITY_GROUPS = 'List Security Groups'
TERMINATE_INSTANCE = 'Terminate Instance'
CREATE_TAGS = 'Create Tags'
AUTHORIZE_SECURITY_GROUP_EGRESS = 'Authorize Security Group Egress'
AUTHORIZE_SECURITY_GROUP_INGRESS = 'Authorize Security Group Ingress'
REVOKE_SECURITY_GROUP_EGRESS = 'Revoke Security Group Egress'
REVOKE_SECURITY_GROUP_INGRESS = 'Revoke Security Group Ingress'

RESERVATIONS = 'Reservations'
SECURITY_GROUP = 'SecurityGroups'
INSTANCES_TABLE_NAME = 'AWS EC2 Instances'
SECURITY_GROUP_TABLE_NAME = 'AWS EC2 Security Groups'
EC2_JSON_INSTANCES = 'EC2_Instances'
EC2_JSON_SECURITY_GROUPS = 'EC2_Security_Groups'
TAG_PREFIX = 'tag:'

ALL_IP_PROTOCOLS = 'all'

IP_PROTOCOLS_MAPPER = {
    'all': '-1'
}

PENDING = 'pending'
RUNNING = 'running'
STOPPED = 'stopped'
STOPPING = 'stopping'
SHUTTING_DOWN = 'shutting-down'
TERMINATED = 'terminated'

# exceptions_codes:
INVALID_INSTANCE_ID = 'InvalidInstanceID'
INVALID_ID = 'InvalidID'
INCORRECT_INSTANCE_STATE = 'IncorrectInstanceState'
TAG_LIMIT_EXCEEDED = 'TagLimitExceeded'
NOT_FOUND = 'NotFound'
INVALID_PARAMETER_VALUE = 'InvalidParameterValue'
INVALID_GROUP_ID = 'InvalidGroupId'
DUPLICATE_RULE = 'InvalidPermission.Duplicate'

INVALID_SECURITY_GROUP_ERROR_CODES = ['InvalidGroup.NotFound', 'InvalidGroupId.Malformed']