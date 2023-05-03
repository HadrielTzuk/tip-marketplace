from exchangelib.services import RULE_CONDITIONS, RULE_ACTIONS

INTEGRATION_NAME = "Exchange"

# Actions name
PING_SCRIPT_NAME = "{} - Ping".format(INTEGRATION_NAME)
SEND_MAIL_SCRIPT_NAME = "{} - Send Email".format(INTEGRATION_NAME)
SEND_EMAIL_AND_WAIT_SCRIPT_NAME = "{} - Send Email And Wait".format(INTEGRATION_NAME)
WAIT_FOR_MAIL_FROM_USER_SCRIPT_NAME = "{} - Wait for mail from user".format(INTEGRATION_NAME)
SEND_MAIL_HTML_SCRIPT_NAME = "{} - Send Mail HTML".format(INTEGRATION_NAME)
GET_MAIL_EML_FILE_SCRIPT_NAME = "{} - Get Mail EML File".format(INTEGRATION_NAME)
SEARCH_MAILS_SCRIPT_NAME = "{} - Search Mails".format(INTEGRATION_NAME)
DELETE_MAIL_SCRIPT_NAME = "{} - Delete Mail".format(INTEGRATION_NAME)
SAVE_MAIL_ATTACHMENTS_TO_THE_CASE_SCRIPT_NAME = "{} - Save Mail Attachments To The Case".format(INTEGRATION_NAME)
MOVE_MAIL_TO_FOLDER_SCRIPT_NAME = "{} - Move Mail To Folder".format(INTEGRATION_NAME)
EXTRACT_EML_DATA_SCRIPT_NAME = "{} - Extract EML Data".format(INTEGRATION_NAME)
DOWNLOAD_ATTACHMENTS_SCRIPT_NAME = "{} - Download Attachments".format(INTEGRATION_NAME)
GET_ACCOUNT_OUT_OF_FACILITY_SETTINGS = "{} - Get Account Out Of Facility Settings".format(INTEGRATION_NAME)
BLOCK_SENDER_BY_MESSAGE_ID_SCRIPT_NAME = "{} - Block Sender by Message ID".format(INTEGRATION_NAME)
UNBLOCK_SENDER_BY_MESSAGE_ID_SCRIPT_NAME = "{} - Unblock Sender by Message ID".format(INTEGRATION_NAME)
ADD_DOMAINS_TO_EXCHANGE_SIEMPLIFY_INBOX_RULES = "{} - Add Domains to Exchange-Siemplify Inbox Rules".format(INTEGRATION_NAME)
REMOVE_DOMAINS_FROM_EXCHANGE_SIEMPLIFY_INBOX_RULES = "{} - Remove Domains from Exchange-Siemplify Inbox Rules".format(INTEGRATION_NAME)
ADD_SENDERS_TO_EXCHANGE_SIEMPLIFY_INBOX_RULES = "{} - Add Senders to Exchange-Siemplify Inbox Rule".format(INTEGRATION_NAME)
REMOVE_SENDERS_FROM_EXCHANGE_SIEMPLIFY_INBOX_RULES = "{} - Remove Senders from Exchange-Siemplify Inbox Rules".format(INTEGRATION_NAME)
GET_AUTHORIZATION_SCRIPT_NAME = "{} - Get Authorization".format(INTEGRATION_NAME)
GENERATE_TOKEN_SCRIPT_NAME = "{} - Generate Token".format(INTEGRATION_NAME)
SEND_VOTE_MAIL_SCRIPT_NAME = "{} - Send Vote Mail".format(INTEGRATION_NAME)
WAIT_FOR_VOTE_MAIL_RESULTS_SCRIPT_NAME = "{} - Wait for Vote Mail Results".format(INTEGRATION_NAME)
SEND_THREAD_REPLY_SCRIPT_NAME = "{} - Send Thread Reply".format(INTEGRATION_NAME)

# Jobs
TOKEN_EXPIRY_NOTIFICATION_SCRIPT_NAME = '{} - Oauth Token Expiry Notification Job'.format(INTEGRATION_NAME)

TOKEN_FILE_PATH = "token_timestamp.json"
DELETE_EXCHANGE_SIEMPLIFY_INBOX_RULES = "{} - Delete Exchange-Siemplify Inbox Rules".format(INTEGRATION_NAME)
LIST_EXCHANGE_SIEMPLIFY_INBOX_RULES = "{} - List Exchange-Siemplify Inbox Rules".format(INTEGRATION_NAME)

PARAMETERS_DEFAULT_DELIMITER = ","
DEFAULT_LIST_DELIMITER = ";"
DEFAULT_URLS_LIST_DELIMITER = "|"
NEW_LINE = "\n"
EXCHLIB_MESSAGE_ID_KEY = "message_id"
ENRICHMENT_TABLE_PREFIX = "Exchange"
MAILBOX_DEFAULT_LIMIT = 25
CHARS_TO_STRIP = " \r\n"
URLS_REGEX = r"(?i)\[?(?:(?:(?:http|https)(?:://))|www\.(?!://))(?:[a-zA-Z0-9\-\._~:;/\?#\[\]@!\$&'\(\)\*\+,=%])+"
URLS_REGEX_COMPLEX = r"(?i)\[?(?:(?:(?:http|https)(?:://))|www\.(?!://))(?:[a-zA-Z0-9\-\._~:;/\?#\[\]@!\$&'\(\)\*\+,=%<>])+"
EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

ALL_AVAILABLE_SENDERS_RULES_STRING = "All available Exchange-Siemplify Senders Rules"
ALL_AVAILABLE_DOMAINS_RULES_STRING = "All available Exchange-Siemplify Domains Rules"
ALL_AVAILABLE_RULES_STRING = "All available Exchange-Siemplify Rules"

RULES = {
    "domains_mark_as_junk": "Siemplify - Domains List - Move To Junk",
    "domains_delete": "Siemplify - Domains List - Delete",
    "domains_permanently_delete": "Siemplify - Domains List - Permanently Delete",
    "senders_mark_as_junk": "Siemplify - Senders List - Move To Junk",
    "senders_delete": "Siemplify - Senders List - Delete",
    "senders_permanently_delete": "Siemplify - Senders List - Permanently Delete",
}

DOMAIN_RULES = [
    RULES.get("domains_mark_as_junk"),
    RULES.get("domains_delete"),
    RULES.get("domains_permanently_delete")
]

SENDER_RULES = [
    RULES.get("senders_mark_as_junk"),
    RULES.get("senders_delete"),
    RULES.get("senders_permanently_delete")
]

ACTIONS = {
    RULES.get("domains_mark_as_junk"): RULE_ACTIONS.get("mark_as_junk"),
    RULES.get("domains_delete"): RULE_ACTIONS.get("delete"),
    RULES.get("domains_permanently_delete"): RULE_ACTIONS.get("permanent_delete"),
    RULES.get("senders_mark_as_junk"): RULE_ACTIONS.get("mark_as_junk"),
    RULES.get("senders_delete"): RULE_ACTIONS.get("delete"),
    RULES.get("senders_permanently_delete"): RULE_ACTIONS.get("permanent_delete"),
}

CONDITIONS = {
    "domain": RULE_CONDITIONS.get("contains_sender_strings"),
    "sender":  RULE_CONDITIONS.get("from_addresses")
}

CORRESPONDING_RULES = {
    RULES.get("senders_mark_as_junk"): RULES.get("domains_mark_as_junk"),
    RULES.get("senders_delete"): RULES.get("domains_delete"),
    RULES.get("senders_permanently_delete"): RULES.get("domains_permanently_delete"),
}

ACTION_NAMES = {
    "move_to_folder": "Move To Folder",
    "delete": "Delete",
    "permanent_delete": "Permanent Delete"
}

VOTING_OPTIONS = {
    "Approve/Reject": b"\x02\x01\x06\x00\x00\x00\x00\x00\x00\x00\x05Reply\x08IPM.Note\x07Message\x02RE\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00f\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x0cReply to All\x08IPM.Note\x07Message\x02RE\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00g\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x07Forward\x08IPM.Note\x07Message\x02FW\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00h\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x0fReply to Folder\x08IPM.Post\x04Post\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00l\x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00\x07Approve\x08IPM.Note\x00\x07Approve\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x04\x00\x00\x00\x06Reject\x08IPM.Note\x00\x06Reject\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\xff\xff\xff\xff\x04\x01\x05R\x00e\x00p\x00l\x00y\x00\x02R\x00E\x00\x0cR\x00e\x00p\x00l\x00y\x00 \x00t\x00o\x00 \x00A\x00l\x00l\x00\x02R\x00E\x00\x07F\x00o\x00r\x00w\x00a\x00r\x00d\x00\x02F\x00W\x00\x0fR\x00e\x00p\x00l\x00y\x00 \x00t\x00o\x00 \x00F\x00o\x00l\x00d\x00e\x00r\x00\x00\x07A\x00p\x00p\x00r\x00o\x00v\x00e\x00\x07A\x00p\x00p\x00r\x00o\x00v\x00e\x00\x06R\x00e\x00j\x00e\x00c\x00t\x00\x06R\x00e\x00j\x00e\x00c\x00t\x00",
    "Yes/No": b'\x02\x01\x06\x00\x00\x00\x00\x00\x00\x00\x05Reply\x08IPM.Note\x07Message\x02RE\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00f\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x0cReply to All\x08IPM.Note\x07Message\x02RE\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00g\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x07Forward\x08IPM.Note\x07Message\x02FW\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00h\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x0fReply to Folder\x08IPM.Post\x04Post\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00l\x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00\x03Yes\x08IPM.Note\x00\x03Yes\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x04\x00\x00\x00\x02No\x08IPM.Note\x00\x02No\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\xff\xff\xff\xff\x04\x01\x05R\x00e\x00p\x00l\x00y\x00\x02R\x00E\x00\x0cR\x00e\x00p\x00l\x00y\x00 \x00t\x00o\x00 \x00A\x00l\x00l\x00\x02R\x00E\x00\x07F\x00o\x00r\x00w\x00a\x00r\x00d\x00\x02F\x00W\x00\x0fR\x00e\x00p\x00l\x00y\x00 \x00t\x00o\x00 \x00F\x00o\x00l\x00d\x00e\x00r\x00\x00\x03Y\x00e\x00s\x00\x03Y\x00e\x00s\x00\x02N\x00o\x00\x02N\x00o\x00'
}

ORIGINAL_EMAIL_EVENT_NAME = "Email Received in Monitoring Mailbox"
ATTACHED_EMAIL_EVENT_NAME = "Attached Email File"
EVENTS_SYSTEM_KEYS = ['device_product', 'device_vendor', 'event_name', 'monitored_mailbox_name', 'original_message_id']
CA_CERTIFICATE_FILE_PATH = "certificate.pem"
KEY_FILE_PATH = "key.pem"

PLACEHOLDER_START = "["
PLACEHOLDER_END = "]"

STORED_IDS_LIMIT = 3000
PRIORITY_DEFAULT = 40
DEFAULT_CHARSET = "utf-8"

URL_ENCLOSING_PREFIX = "["
URL_ENCLOSING_SUFFIX = "]"
