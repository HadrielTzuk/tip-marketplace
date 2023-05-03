INTEGRATION_NAME = "ZohoDesk"
INTEGRATION_DISPLAY_NAME = "Zoho Desk"

# Actions
PING_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Ping"
GET_REFRESH_TOKEN_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Get Refresh Token"
UPDATE_TICKET_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Update Ticket"
GET_TICKET_DETAILS_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Get Ticket Details"
MARK_TICKET_AS_SPAM_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Mark Ticket As Spam"
ADD_COMMENT_TO_TICKET_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Add Comment To Ticket"
CREATE_TICKET_SCRIPT_NAME = f"{INTEGRATION_DISPLAY_NAME} - Create Ticket"

ENDPOINTS = {
    "ping": "/api/v1/agents",
    "get_ticket_details": "/api/v1/tickets/{ticket_id}",
    "get_ticket_comments": "/api/v1/tickets/{ticket_id}/comments",
    "mark_as_spam": "/api/v1/tickets/markSpam",
    "mark_as_read": "api/v1/tickets/{ticket_id}/markAsRead",
    "mark_as_unread": "api/v1/tickets/{ticket_id}/markAsUnRead",
    "add_comment": "/api/v1/tickets/{ticket_id}/comments",
    "get_departments": "/api/v1/departments",
    "get_contacts": "/api/v1/contacts",
    "get_products": "/api/v1/products",
    "get_agents": "/api/v1/agents",
    "get_teams": "/api/v1/teams",
    "create_ticket": "/api/v1/tickets"
}

OAUTH_URL = "https://accounts.zoho.{region}/oauth/v2/token"
ERROR_KEY = "error"
POSSIBLE_FIELDS = ["contacts", "products", "assignee", "departments", "contract", "isread", "team", "skills"]
MAX_LIMIT = 100
DEFAULT_LIMIT = 50
PUBLIC_VISIBILITY = "Public"
CONTENT_TYPE_MAPPING = {
    "Plain Text": "plainText",
    "HTML": "html"
}

PRIORITY_MAPPING = {
    "No Priority": None,
    "Low": "Low",
    "Medium": "Medium",
    "High": "High"
}

CLASSIFICATION_MAPPING = {
    "No Classification": None,
    "Question": "Question",
    "Problem": "Problem",
    "Feature": "Feature",
    "Others": "Others"
}
AGENT_TYPE_ASSIGNEE = "Agent"
TEAM_TYPE_ASSIGNEE = "Team"
ASSIGNEE_TYPE_MAPPING = {
    "Select One": None,
    AGENT_TYPE_ASSIGNEE: AGENT_TYPE_ASSIGNEE,
    TEAM_TYPE_ASSIGNEE: TEAM_TYPE_ASSIGNEE
}

READ = "Read"
UNREAD = "Unread"
MARK_STATE_MAPPING = {
    READ: "Read",
    UNREAD: "Unread"
}
