INTEGRATION_NAME = 'MicrosoftTeams'
INTEGRATION_DISPLAY_NAME = "Microsoft Teams"
WAIT_REPLY_SCRIPT = '{} - Wait For Reply'.format(INTEGRATION_NAME)
SEND_MESSAGE_ACTION = '{} - Send Message'.format(INTEGRATION_NAME)
WAIT_FOR_REPLY_ACTION = '{} - Wait For Reply'.format(INTEGRATION_NAME)
LIST_USERS_ACTION = '{} - List Users'.format(INTEGRATION_NAME)
LIST_TEAMS_ACTION = '{} - List Teams'.format(INTEGRATION_NAME)
LIST_CHANNELS_ACTION = '{} - List Channels'.format(INTEGRATION_NAME)
GET_USER_DETAILS_ACTION = '{} - Get User Details'.format(INTEGRATION_NAME)
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
GET_TEAM_DETAILS_ACTION = '{} - Get Team Details'.format(INTEGRATION_NAME)
GENERATE_TOKEN_ACTION = '{} - Generate Token'.format(INTEGRATION_NAME)
GET_AUTHORIZATION_ACTION = '{} - Get Authorization'.format(INTEGRATION_NAME)
SEND_CHAT_MESSAGE_ACTION = '{} - Send Chat Message'.format(INTEGRATION_NAME)
SEND_USER_MESSAGE_ACTION = '{} - Send User Message'.format(INTEGRATION_NAME)
LIST_CHATS_ACTION = '{} - List Chats'.format(INTEGRATION_NAME)
CREATE_CHANNEL_ACTION = '{} - Create Channel'.format(INTEGRATION_NAME)
DELETE_CHANNEL_ACTION = '{} - Delete Channel'.format(INTEGRATION_NAME)
ADD_USERS_TO_CHANNEL_ACTION = '{} - Add Users To Channel'.format(INTEGRATION_NAME)
REMOVE_USERS_FROM_CHANNEL_ACTION = '{} - Remove Users From Channel'.format(INTEGRATION_NAME)
CREATE_CHAT_ACTION = '{} - Create Chat'.format(INTEGRATION_NAME)

CHECK_FIRST_REPLY = 'Check First Reply'
WAIT_TILL_TIMEOUT = 'Wait Till Timeout'
TIMEOUT_BUFFER_IN_SECONDS = 45
DEFAULT_TIMEOUT = 300
EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

CHAT_TYPES = {
    "All": None,
    "Group Chat":"group",
    "Meeting Chat":"meeting",
    "One on One Chat":"oneOnOne"
    
}

EQUAL_FILTER = "Equal"
CONTAINS_FILTER = "Contains"
NOT_SPECIFIED_FILTER = "Not Specified"

FILTER_KEY_TOPIC = "Topic"
FILTER_KEY_MEMBER_EMAIL = "Member Email"
FILTER_KEY_MEMBER_DISPLAY_NAME = "Member Display Name"
FILTER_KEY_SELECT_ONE_FILTER = "Select One"
PRIVATE_MEMBERSHIP_TYPE = "private"
