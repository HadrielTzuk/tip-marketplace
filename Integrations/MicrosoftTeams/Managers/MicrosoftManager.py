# =====================================
#              IMPORTS                #
# =====================================
from copy import deepcopy
import requests
import json
from MicrosoftExceptions import (
    MicrosoftTeamsManagerError,
    MicrosoftTeamsChannelNotFoundError,
    MicrosoftTeamsMessageNotFoundError,
    MicrosoftTeamsTeamNotFoundError,
    MicrosoftTeamsClientError
)
from MicrosoftTeamsParser import MicrosoftTeamsParser
from MicrosoftConstants import CHAT_TYPES

from datamodels import Message

# =====================================
#             CONSTANTS               #
# =====================================
# Access consts
SCOPE_BEHALF_USER = [
    'https://graph.microsoft.com/.default'
]

TOKEN_PAYLOAD = {"client_id": None,
                 "scope": ' '.join(SCOPE_BEHALF_USER),
                 "client_secret": None,
                 "grant_type": "authorization_code",
                 "code": None,
                 "redirect_uri": None}

REFRESH_PAYLOAD = {"client_id": None,
                   "scope": ' '.join(SCOPE_BEHALF_USER),
                   "refresh_token": None,
                   "client_secret": None,
                   "grant_type": "refresh_token",
                   "redirect_uri": None}

HEADERS = {"Content-Type": "application/json"}
VERSION = 'beta'
INVALID_REFRESH_TOKEN_ERROR = 'Refresh Token is malformed or invalid'

MESSAGE_REQ_BODY = {"body": {"content": None}}

# urls
URL_AUTHORIZATION = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&response_mode=query" + "&scope={scope}".format(scope='%20'.join(SCOPE_BEHALF_USER))
ACCESS_TOKEN_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/token'
GET_USER_URL = 'https://graph.microsoft.com/{version}/users/{userID}'
LIST_USERS_URL = 'https://graph.microsoft.com/{version}/users'
LIST_CHANNELS_URL = 'https://graph.microsoft.com/{version}/teams/{team_id}/channels'
LIST_TEAMS_URL = "https://graph.microsoft.com/{version}/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"
GET_TEAM_URL = 'https://graph.microsoft.com/{version}/teams/{team_id}'
POST_MSG_URL = 'https://graph.microsoft.com/{version}/teams/{team_id}/channels/{channel_id}/messages'
GET_MSG_URL = 'https://graph.microsoft.com/{version}/teams/{team_id}/channels/{channel_id}/messages/{message_id}'
MSG_REPLIES_URL = 'https://graph.microsoft.com/{version}/teams/{team_id}/channels/{channel_id}/messages/{message_id}/replies'
GET_USER_ID_URL = "https://graph.microsoft.com/{version}/users?$filter=displayName eq '{user_name}'&$select=id,displayName"
GET_TEAM_ID_URL = "https://graph.microsoft.com/{version}/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team') and displayName eq '{team_name}'&select=id,displayName"
GET_CHANNEL_ID_URL = "https://graph.microsoft.com/{version}/teams/{team_id}/channels?$filter=displayName eq '{channel_name}'&$select=id,displayName"
CHANNEL_MESSAGES_URL = "https://graph.microsoft.com/v1.0/chats/{chat_id}/messages"
CHECK_ACCOUNT_URL = "https://graph.microsoft.com/v1.0/me"
LIST_CHANNELS_TO_SEND_MESSAGE_URL = "https://graph.microsoft.com/v1.0/me/chats?$expand=members&$filter=chatType eq 'oneOnOne'"
LIST_CHATS_URL = "https://graph.microsoft.com/v1.0/me/chats"
CREATE_CHANNEL_URL = "https://graph.microsoft.com/{version}/teams/{team_id}/channels"
DELETE_CHANNEL_URL = "https://graph.microsoft.com/{version}/teams/{team_id}/channels/{channel_id}"
MANAGE_CHANNEL_USERS = "https://graph.microsoft.com/{version}/teams/{team_id}/channels/{channel_id}/members"
USER_DATA_BIND = "https://graph.microsoft.com/{version}/users('{user_id}')"
REMOVE_USER_FROM_CHANNEL = "https://graph.microsoft.com/{version}/teams/{team_id}/channels/{channel_id}/members/{user_id}"
MANAGE_CHATS_URL = "https://graph.microsoft.com/{version}/chats"
FIND_USER_ID_URL = "https://graph.microsoft.com/v1.0/users?$filter=displayName eq '{user_name}' or userPrincipalName eq '{user_name}' or mail eq '{user_name}'&$select=id,displayName,mail,userPrincipalName"

# =====================================
#              CLASSES                #
# =====================================

class MicrosoftTeamsManager(object):
    def __init__(self, client_id, client_secret, tenant, refresh_token, redirect_url, verify_ssl=False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant = tenant
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.parser = MicrosoftTeamsParser()
        self.access_token = self.refresh_token(refresh_token, redirect_url)

    @staticmethod
    def get_access_token_behalf_user(code, client_id, client_secret, tenant, redirect_url):
        """
        Use the authorization code to request an access token
        :param code: {string} The authorization_code
        :param client_id: {string} The Application ID that the registration portal
        :param client_secret: {string} The application secret that you created in the app registration portal for your app.
        :param tenant: {string} domain name from azure portal
        :param redirect_url: The Redirect URL that will be used to authenticate integration.
        :return: {string} An OAuth 2.0 refresh token. Refresh tokens are long-lived, and can be used to retain access to resources.
        """
        payload = deepcopy(TOKEN_PAYLOAD)
        payload["client_id"] = client_id
        payload["client_secret"] = client_secret
        payload["code"] = code
        payload["redirect_uri"] = redirect_url

        res = requests.post(ACCESS_TOKEN_URL.format(tenant=tenant), data=payload)
        res.raise_for_status()
        return res.json().get('refresh_token')

    def refresh_token(self, refresh_token, redirect_url):
        """
        Access tokens are short lived, and you must refresh them after they expire to continue accessing resources
        :param refresh_token: {string} The refresh_token that you acquired during the token request.
        :param redirect_url: The Redirect URL that will be used to authenticate integration.
        :return: {string} Access token. The app can use this token in calls to Microsoft Graph.
        """
        payload = deepcopy(REFRESH_PAYLOAD)
        payload["client_id"] = self.client_id
        payload["refresh_token"] = refresh_token
        payload["client_secret"] = self.client_secret
        payload["redirect_uri"] = redirect_url

        res = self.session.post(ACCESS_TOKEN_URL.format(tenant=self.tenant), data=payload)

        # Validate token lifetime.
        if INVALID_REFRESH_TOKEN_ERROR in res.text:
            raise MicrosoftTeamsManagerError("ERROR! Refresh token is invalid or malformed. (Token is valid only for 90 days, please renew your refresh token)")

        access_token = res.json()['access_token']
        self.session.headers.update({"Authorization": "Bearer {0}".format(access_token)})
        return access_token

    @staticmethod
    def validate_response(response, custom_exception=MicrosoftTeamsManagerError, handle_client_error=False):
        """
        Validate response
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            if response.status_code == 400 and handle_client_error:
                raise MicrosoftTeamsClientError(
                    json.loads(error.response.content).get("error", {}).get("innerError", {}).get("message", "")
                    or json.loads(error.response.content).get("error", {}).get("message", "")
                )
            if response.status_code == 404:
                raise MicrosoftTeamsChannelNotFoundError(error)

            raise custom_exception("Error:{0}, response:{1}".format(error, error.response.content))

    def list_users(self, max_users_to_return=None):
        """
        Retrieve a list of user objects.
        :param max_users_to_return {int} Maximum users to return
        :return: {list} of users {dict}
        """
        url = LIST_USERS_URL.format(version=VERSION)
        results = self._paginate_results(url=url, limit=max_users_to_return)
        return results

    def get_user_id(self, user_name):
        """
        Get user id by user name
        :param user_name: {string} user name
        :return: {string} user id if exist
        """

        url = GET_USER_ID_URL.format(version=VERSION, user_name=user_name)
        response = self.session.get(url)
        self.validate_response(response)
        
        users = response.json().get("value")

        for user in users:
            if user.get("displayName") == user_name:
                return user.get("id")

        raise MicrosoftTeamsManagerError("User not found")

    def find_user_id(self, user_name):
        """
        Find user id by user name
        :param user_name: {string} user name
        :return: {string} user id if exist
        """

        url = FIND_USER_ID_URL.format(version=VERSION, user_name=user_name)
        response = self.session.get(url)
        self.validate_response(response)

        users = response.json().get("value")

        for user in users:
            if user_name in [user.get("displayName"), user.get("userPrincipalName"), user.get("mail")]:
                return user.get("id")

        raise MicrosoftTeamsManagerError("User not found")

    def get_user_details(self, user_name):
        """
        Retrieve the properties and relationships of user object.
        :param user_name: {string} user name
        :return: {dict} user details
        """
        user_id = self.get_user_id(user_name=user_name)
        list_users_url = GET_USER_URL.format(version=VERSION, userID=user_id)
        response = self.session.get(list_users_url)
        self.validate_response(response)
        return response.json()

    def list_channels(self, team_name, max_channels_to_return):
        """
        Retrieve the list of channels in specific team.
        :param team_name: {string} team name
        :param max_channels_to_return: {int} Maxumim channels to return
        :return: {list} of channels {dict}
        """
        # Get team id by name
        team_id = self.get_team_id(team_name)
        url = LIST_CHANNELS_URL.format(version=VERSION, team_id=team_id)

        teams_response = self.session.get(url)
        self.validate_response(teams_response)
        results = teams_response.json().get('value')
        
        if max_channels_to_return:
            results = results[:max_channels_to_return]
        
        return results
    
    def list_teams(self, max_teams_to_return):
        """
        Retrieve a list of teams objects.
        :param max_teams_to_return: {int} Maximum teams to return
        :return: {list} of teams {dict}
        """
        
        url = LIST_TEAMS_URL.format(version=VERSION)
        results = self._paginate_results(url=url, limit=max_teams_to_return)
        return results

    def _paginate_results(self, url, limit=None, method="GET"):
        """
        Paginate the results of a job
        :param url: {str} The url to send request to
        :param limit: {int} The limit of the results to fetch
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :return: {list} List of results
        """
        response = self.session.request(method, url)
        self.validate_response(response)
        json_result = response.json()
        results = json_result.get("value", [])  
        next_url = json_result.get("@odata.nextLink")              

        while True:
            if limit and len(results) >= limit:
                break
            if not next_url:
                break
            url = next_url
            response = self.session.request(method, url)
            self.validate_response(response)
            json_result = response.json()
            next_url = json_result.get("@odata.nextLink") 
            results.extend(json_result.get("value", []))  

        return results[:limit] if limit else results

    def get_team_id(self, team_name):
        """
        Get team id by team name
        :param team_name: {string} team name
        :return: {string} team id if exist
        """

        url = GET_TEAM_ID_URL.format(version=VERSION, team_name=team_name)
        response = self.session.get(url)
        self.validate_response(response)
        
        teams = response.json().get("value")

        for team in teams:
            if team.get("displayName") == team_name:
                return team.get("id")

        raise MicrosoftTeamsTeamNotFoundError("No team was found")

    def get_team_details(self, team_name):
        """
        Retrieve the properties team object.
        :param team_name: {string} team name
        :return: {dict} team details
        """
        # Get team id by name
        team_id = self.get_team_id(team_name)
        get_team_url = GET_TEAM_URL.format(version=VERSION, team_id=team_id)
        response = self.session.get(get_team_url)
        self.validate_response(response)
        return response.json()

    def send_message(self, channel_name, team_name, message):
        """
        Post message to specific channel in specific team
        :param channel_name: {string} channel name
        :param team_name: {string} team name
        :param message: {string} message to post
        :return: {dict} with message id
        """
        # Note:
        # Future API releases will support reading existing chatThreads and
        # r/w direct chats between users that are outside the scope of a team or channel.

        # Get team id by name
        team_id = self.get_team_id(team_name)
        # Get channel id by name
        channel_id = self.get_channel_id(team_id, channel_name)

        MESSAGE_REQ_BODY['body']['content'] = message
        self.session.headers.update(HEADERS)
        post_msg_url = POST_MSG_URL.format(version=VERSION, team_id=team_id, channel_id=channel_id)
        res = self.session.post(post_msg_url, json=MESSAGE_REQ_BODY)
        self.validate_response(res)
        return res.json()

    def get_message_by_id(self, team_id, channel_id, message_id):
        response = self.session.get(
            GET_MSG_URL.format(
                version=VERSION,
                team_id=team_id,
                channel_id=channel_id,
                message_id=message_id
            )
        )

        self.validate_response(response, MicrosoftTeamsMessageNotFoundError)

        return response.json().get('id')

    def get_channel_id(self, team_id, channel_name):
        """
        Get channel id for a particular team
        :param team_id: {string} ID of the team
        :param channel_name: {string} channel name
        :return: {string} channel id
        """

        url = GET_CHANNEL_ID_URL.format(version=VERSION, team_id=team_id, channel_name=channel_name)
        response = self.session.get(url)
        self.validate_response(response)
        
        channels = response.json().get("value")

        for channel in channels:
            if channel.get("displayName") == channel_name:
                return channel.get("id")

        raise MicrosoftTeamsTeamNotFoundError("No channel was found")

    def get_channel_by_channel_name(self, team_id, channel_name):
        """
        Get channel for a particular team by channel name
        :param team_id: {string} team ID
        :param channel_name: {string} channel name
        :return: {dict} the channel data
        """
        url = LIST_CHANNELS_URL.format(version=VERSION, team_id=team_id)
        response = self.session.get(url)
        self.validate_response(response)

        for channel in response.json().get("value"):
            if channel.get("displayName") == channel_name:
                return channel

        raise MicrosoftTeamsChannelNotFoundError("No channel was found")

    def get_message_replies(self, team_name, channel_name, message_id):
        team_id = self.get_team_id(team_name)
        channel_id = self.get_channel_id(team_id, channel_name)
        message_id = self.get_message_by_id(team_id, channel_id, message_id)

        response = self.session.get(
            MSG_REPLIES_URL.format(
                version=VERSION,
                team_id=team_id,
                channel_id=channel_id,
                message_id=message_id
            )
        )

        self.validate_response(response)

        return response.json().get('value', [])

    def send_message_to_chat(
            self,
            chat_id: str,
            message: str,
            content_type: str
    ) -> Message:
        """
        Function that sends a message to a chat
        Args:
            chat_id: ID of the chat to send a message
            message: Message content
            content_type: Message type (e.g. text, html)

        Returns:
            (Message)
        """
        url = CHANNEL_MESSAGES_URL.format(chat_id=chat_id)
        self.session.headers.update(HEADERS)
        payload = json.dumps({
            "body": {
                "contentType": content_type,
                "content": message
            }
        })
        
        response = self.session.post(url, data=payload)
        self.validate_response(response)
        
        return self.parser.build_message_object(raw_json=response.json())

    def get_chat_messages(self, chat_id):
        """
        Function that gets chat messages
        :param chat_id: {string} ID of the chat 
        :return: {Message} Message object
        """
        url = CHANNEL_MESSAGES_URL.format(chat_id=chat_id)
        self.session.headers.update(HEADERS)

        response = self.session.get(url)
        self.validate_response(response)
        
        chat_messages = response.json().get("value")
        
        if chat_messages is not None:
            return self.parser.build_message_object(raw_json=chat_messages[0])

    def check_account(self):
        """
        Function that information about the account
        :return: {Me} Me siemplify object
        """
        response = self.session.get(CHECK_ACCOUNT_URL)
        self.validate_response(response)
        
        return self.parser.build_me_object(response.json())
    
    def get_chat_id(self, entity_identifier):
        """
        Function that gets the correct chat id to which a message should be sent
        :param entity_identifier: {string} Entity identifier for which we want to get the chat id
        :return: {str} Chat ID
        """
        response = self.session.get(LIST_CHANNELS_TO_SEND_MESSAGE_URL)
        self.validate_response(response)
        
        return self.parser.get_chat_ids(raw_json=response.json(), entity_identifier=entity_identifier)

    def get_chats(self, chat_type, filter_key, filter_value, filter_logic, limit):
        """
        Function that get all the chats based on the criteria 
        :param chat_type: {string} Chat Type: Meeting, Group, OneOnOne, All
        :param filter_key: {string} Filter Key
        :param filter_value: {string} Filter Value
        :param filter_logic: {string} Filter logic to use
        :param limit: {int} Limit of how many chats to return    
        :return: {List} List of filtered chat objects
        """        
        
        chat_type_filter = CHAT_TYPES.get(chat_type)
        params = {
            "$expand":"members"
            
        }
        if chat_type_filter is not None:
            params["$filter"] = f"chatType eq '{chat_type_filter}'"
            
        response = self.session.get(LIST_CHATS_URL, params=params)
        self.validate_response(response)
        return self.parser.build_chat_objects(raw_json=response.json(), filter_key=filter_key, filter_value=filter_value, filter_logic=filter_logic, limit=limit)

    def create_channel(self, team_id, channel_name, channel_type, description):
        """
        Create channel
        :param team_id: {string} team ID
        :param channel_name: {string} channel name
        :param channel_type: {string} channel type
        :param description: {string} channel description
        """
        url = CREATE_CHANNEL_URL.format(version=VERSION, team_id=team_id)
        payload = {
            "displayName": channel_name,
            "membershipType": channel_type,
            "description": description or ""
        }

        response = self.session.post(url, json=payload)
        self.validate_response(response, handle_client_error=True)
        return self.parser.build_channel_object(response.json())

    def delete_channel(self, team_id, channel_id):
        """
        Delete channel
        :param team_id: {string} team ID
        :param channel_id: {string} channel ID
        :return: {void}
        """
        url = DELETE_CHANNEL_URL.format(version=VERSION, team_id=team_id, channel_id=channel_id)
        response = self.session.delete(url)
        self.validate_response(response, handle_client_error=True)

    def add_user_to_channel(self, team_id, channel_id, user_id):
        """
        Add user to channel
        :param team_id: {string} team ID
        :param channel_id: {string} channel ID
        :param user_id: {string} user ID
        :return: {void}
        """
        url = MANAGE_CHANNEL_USERS.format(version=VERSION, team_id=team_id, channel_id=channel_id)
        payload = {
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "user@odata.bind": USER_DATA_BIND.format(version=VERSION, user_id=user_id)
        }

        response = self.session.post(url, json=payload)
        self.validate_response(response, handle_client_error=True)

    def remove_user_from_channel(self, team_id, channel_id, user_id):
        """
        Remove user from channel
        :param team_id: {string} team ID
        :param channel_id: {string} channel ID
        :param user_id: {string} user ID
        :return: {void}
        """
        url = REMOVE_USER_FROM_CHANNEL.format(version=VERSION, team_id=team_id, channel_id=channel_id, user_id=user_id)
        response = self.session.delete(url)
        self.validate_response(response, handle_client_error=True)

    def get_channel_users(self, team_id, channel_id):
        """
        Get users from particular channel
        :param team_id: {string} team ID
        :param channel_id: {string} channel ID
        :return: {list} list of User objects
        """
        url = MANAGE_CHANNEL_USERS.format(version=VERSION, team_id=team_id, channel_id=channel_id)
        results = self._paginate_results(url=url)
        return self.parser.build_user_objects(results)

    def create_chat(self, user_ids):
        """
        Create chat
        :param user_ids: {list} list of user ids
        :return: {Chat} Chat object
        """
        url = MANAGE_CHATS_URL.format(version=VERSION)
        payload = {
            "chatType": "oneOnOne",
            "members": [{
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "roles": ["owner"],
                "user@odata.bind": USER_DATA_BIND.format(version=VERSION, user_id=user_id)
            } for user_id in user_ids]
        }

        response = self.session.post(url, json=payload)
        self.validate_response(response, handle_client_error=True)
        return self.parser.build_chat_object(response.json())
