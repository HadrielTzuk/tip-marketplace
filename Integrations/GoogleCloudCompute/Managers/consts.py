INTEGRATION_NAME = "Google Cloud Compute"

API_URL = 'https://compute.googleapis.com/'
SCOPES = ["https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/cloud-platform"]


DEFAULT_ORDER = "creationTimestamp desc"
DEFAULT_MAX_RESULT = 50
DEFAULT_PAGE_SIZE = 50
DEFAULT_MIN_RESULT = 0

LIST_INSTANCES_TABLE_NAME = "Google Cloud Compute Instances"
GET_INSTANCE_IAM_POLICY_SCRIPT_NAME = "Get Instance IAM Policy"
SET_INSTANCE_IAM_POLICY_SCRIPT_NAME = "Set Instance IAM Policy"
ADD_LABELS_TO_INSTANCE_SCRIPT_NAME = "Add Labels To Instance"
ENRICHMENT_CSV_TABLE_NAME = "{} Enrichment Table"

INVALID_ZONE_ERROR = 'Unknown zone'
INVALID_LABELS_ERROR = "Invalid value for field 'labels'"
NOT_FOUND_RESOURCE_ERROR = ["The resource", "was not found"]

COLON = ":"

# Instance Status:
RUNNING_STATUS = "RUNNING"

ENRICHMENT_PREFIX = 'Google_Compute'
