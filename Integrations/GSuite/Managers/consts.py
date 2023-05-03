INTEGRATION_NAME = "GSuite"
ENRICHMENT_PREFIX = INTEGRATION_NAME

# Action Script Names
PING_SCRIPT_NAME = "Ping"
GET_AUTHORIZATION_SCRIPT_NAME = "Get Authorization"
GENERATE_TOKEN_SCRIPT_NAME = "Generate Token"
DELETE_USER_SCRIPT_NAME = "Delete User"
DELETE_OU_SCRIPT_NAME = "Delete OU"
CREATE_OU_SCRIPT_NAME = "Create OU"
CREATE_USER_SCRIPT_NAME = "Create User"
CREATE_GROUP_SCRIPT_NAME = "Create Group"
UPDATE_OU_SCRIPT_NAME = "Update OU"
UPDATE_USER_SCRIPT_NAME = "Update User"
ADD_MEMBERS_TO_GROUP_SCRIPT_NAME = "Add Members To Group"
REMOVE_MEMBERS_FROM_GROUP_SCRIPT_NAME = "Remove Members From Group"
LIST_OU_SCRIPT_NAME = "List Organization Units"
DELETE_GROUP_SCRIPT_NAME = "Delete Group"
LIST_USERS_SCRIPT_NAME = "List Users for an Account"
LIST_GROUP_MEMBERS_SCRIPT_NAME = "List Group Members"
ENRICH_ENTITIES_SCRIPT_NAME = "Enrich Entities"

SHA256_HASH_FUNCTION = 'crypt'

# API status codes
API_CONFLICT_STATUS_CODE = 409
API_NOT_FOUND_STATUS_CODE = 404
API_BAD_REQUEST_STATUS_CODE = 400
API_NOT_AUTHORIZED_STATUS_CODE = 403

DEFAULT_MAX_USERS_TO_RETURN = 20

# Query operator mapping
SPACE = " "
TRUE = "true"
FALSE = "false"
AND = "AND"
OR = "OR"
EQUAL = "="
CONTAINS = ":"

# GSuite authorization link
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&scope=https://www.googleapis.com/auth/admin.directory.group.member%20https://www.googleapis.com/auth/admin.directory.group%20https://www.googleapis.com/auth/admin.directory.orgunit%20https://www.googleapis.com/auth/admin.directory.user%20https://www.googleapis.com/auth/admin.directory.user.alias&include_granted_scopes=true&redirect_uri={redirect_uri}&response_type=code&client_id={client_id}"
USER_STATUS_TO_SUSPENDED = {
    "Not Changed": None,
    "Blocked": True,
    "Unblocked": False
}
