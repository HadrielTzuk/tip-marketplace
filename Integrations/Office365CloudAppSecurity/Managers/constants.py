INTEGRATION_NAME = "Office365CloudAppSecurity"
INTEGRATION_DISPLAY_NAME = "Office 365 CloudApp Security"
PRODUCT = 'Microsoft Cloud App Security'


# Action Script Names
LIST_FILES_SCRIPT_NAME = f"{INTEGRATION_NAME} - List Files"
ADD_IP_TO_IP_ADDRESS_RANGE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Add IP To IP Address Range"
REMOVE_IP_FROM_IP_ADDRESS_RANGE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Remove IP From IP Address Range"


FILTER_KEY_MAPPING = {
    "Select One": "",
    "ID": "fileId",
    "Filename": "filename",
    "File Type": "fileType",
    "Share Status": "sharing"
}

FILTER_KEY_RESPONSE_KEY_MAPPING = {
    "fileId": "id",
    "filename": "name"
}

FILTER_STRATEGY_MAPPING = {
    "Not Specified": "",
    "Equal": "Equal",
    "Contains": "Contains"
}

DEFAULT_LIMIT = 50
MAX_LIMIT = 1000
EQUAL = "Equal"
CONTAINS = "Contains"
FILETYPE_FILTER_KEY = "File Type"
SHARE_STATUS_FILTER_KEY = "Share Status"

FILE_TYPE_MAPPING = {
    "other": 0,
    "document": 1,
    "spreadsheet": 2,
    "presentation": 3,
    "text": 4,
    "image": 5,
    "folder": 6
}

SHARE_STATUS_MAPPING = {
    "private": 0,
    "internal": 1,
    "external": 2,
    "public": 3,
    "public (internet)": 4
}

CATEGORY_MAPPING = {
    "Corporate": 1,
    "Administrative": 2,
    "Risky": 3,
    "VPN": 4,
    "Cloud provider": 5,
    "Other": 6
}

POSSIBLE_FILE_TYPES = ["other", "document", "spreadsheet", "presentation", "text", "image", "folder"]
POSSIBLE_SHARE_STATUSES = ["private", "internal", "external", "public", "public (internet)"]
