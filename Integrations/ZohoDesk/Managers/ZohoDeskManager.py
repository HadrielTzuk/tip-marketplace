import datetime
from urllib.parse import urljoin, urlparse

import requests

from UtilsManager import validate_response
from ZohoDeskExceptions import ZohoDeskException
from ZohoDeskParser import ZohoDeskParser
from constants import ENDPOINTS, OAUTH_URL, ERROR_KEY


class ZohoDeskManager:
    def __init__(self, api_root, client_id, client_secret, refresh_token, verify_ssl, siemplify_logger=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} Zoho Desk API root
        :param client_id: {str} Client ID of the Zoho Desk account.
        :param client_secret: {str} Client secret of the Zoho Desk account.
        :param refresh_token: {str} Refresh token for the OAuth authorization.
        :param verify_ssl: {bool} Specifies if certificate that is configured on the api root should be validated
        :param siemplify_logger: Siemplify logger
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.verify_ssl = verify_ssl
        self.siemplify_logger = siemplify_logger
        self.parser = ZohoDeskParser()
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if not refresh_token:
            raise Exception('In order to authenticate, you need to provide \"Refresh Token\". '
                            'It can be generated via action \"Get Refresh Token\". For now you can put dummy data '
                            'in that field. For more information, please visit our doc portal.')
        self.session.headers.update(
            {"Authorization": f"Zoho-oauthtoken {self.get_access_token(client_id, client_secret, refresh_token)}"})

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def _extract_region_from_api_root(self):
        """
        Extract region from provided api root.
        :return: {str} Region slug(eu, com)
        """
        parsed_uri = urlparse(self.api_root)
        return parsed_uri.netloc.split(".")[-1]

    def get_access_token(self, client_id, client_secret, refresh_token):
        """
        Obtain the access token
        :param client_id: {str} The client id to authenticate with
        :param client_secret: {str} The secret of the given client id
        :param refresh_token: {str} The current refresh token
        :return: {str} The new access token
        """
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        region = self._extract_region_from_api_root()
        response = self.session.post(OAUTH_URL.format(region=region), data=data)
        self.validate_access_token_response(response, "Unable to obtain access token")
        return response.json().get('access_token', '')

    @staticmethod
    def obtain_refresh_token(client_id, client_secret, code, auth_link, verify_ssl):
        """
        Obtain a refresh token
        :param client_id: {str} The client id to authenticate with
        :param client_secret: {str} The secret of the given client id
        :param code: {str} The generated code from the authorizing step
        :param auth_link: {str} The authorization link for the integration
        :param verify_ssl: {bool} Specifies if certificate that is configured on the api root should be validated
        :return: {str} The new refresh token
        """
        data = {
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "authorization_code",
        }
        response = requests.post(auth_link, data=data, verify=verify_ssl)
        ZohoDeskManager.validate_access_token_response(response, error_msg="Unable to obtain refresh token")
        return response.json().get('refresh_token', '')

    @staticmethod
    def validate_access_token_response(response, error_msg="An error occurred"):
        """
        Validate the access token response
        :param response: {requests.Response} The response
        :param error_msg: {str} The error message to display on failure
        """
        try:
            response.raise_for_status()

            if response.status_code == 200 and ERROR_KEY in response.json():
                raise ZohoDeskException(f"{error_msg}: {response.json().get(ERROR_KEY, '')}")
        except requests.HTTPError as error:
            try:
                response.json()
            except:
                # Not a JSON - return content
                raise ZohoDeskException(f"{error_msg}: {error} - {error.response.content}")

            raise ZohoDeskException(f"{error_msg}: {error} {response.json().get(ERROR_KEY)}")

    def test_connectivity(self):
        """
        Test connectivity
        :return: {void}
        """
        url = self._get_full_url("ping")
        response = self.session.get(url)
        validate_response(response)

    def get_ticket(self, ticket_id, additional_fields):
        """
        Get ticket by id
        :param ticket_id: {str} ticket id
        :param additional_fields: {str} additional fields to return
        :return: {Ticket} Ticket object
        """
        url = self._get_full_url("get_ticket_details", ticket_id=ticket_id)
        params = {"include": additional_fields} if additional_fields else {}
        response = self.session.get(url, params=params)
        validate_response(response)
        return self.parser.build_ticket_object(response.json())

    def get_ticket_comments(self, ticket_id, limit):
        """
        Get ticket by id
        :param ticket_id: {str} ticket id
        :param limit: {int} how many comments to return
        :return: {list} List of dicts
        """
        url = self._get_full_url("get_ticket_comments", ticket_id=ticket_id)
        params = {
            "limit": limit
        }
        response = self.session.get(url, params=params)
        validate_response(response)
        return self.parser.build_results(response.json(), 'build_comment_object')

    def mark_ticket_as_spam(self, ticket_id, mark_contact, mark_other_contact_tickets):
        """
        Mark ticket as spam
        :param ticket_id: {str} ticket id
        :param mark_contact: {bool} if true, will mark the contact as spammer
        :param mark_other_contact_tickets: {bool} if true, will mark all the existing tickets from the same contact as spam
        :return: {void}
        """
        url = self._get_full_url("mark_as_spam")
        payload = {
            "contactSpam": mark_contact,
            "handleExistingTickets": mark_other_contact_tickets,
            "ids": [
                ticket_id
            ],
            "isSpam": "true"
        }

        response = self.session.post(url, json=payload)
        validate_response(response)

    def mark_ticket_as_read(self, ticket_id):
        """
        Mark ticket as read
        @param ticket_id: Ticket ID
        @return: None
        """
        response = self.session.post(
            self._get_full_url("mark_as_read", ticket_id=ticket_id)
        )
        validate_response(response)
        return True

    def mark_ticket_as_unread(self, ticket_id):
        """
        Mark ticket as unread
        @param ticket_id: Ticket ID
        @return: None
        """
        response = self.session.post(
            self._get_full_url("mark_as_unread", ticket_id=ticket_id)
        )
        validate_response(response)
        return True

    def update_ticket(
            self,
            ticket_id,
            title=None,
            description=None,
            department=None,
            contact=None,
            agent=None,
            team=None,
            resolution=None,
            priority=None,
            status=None,
            classification=None,
            channel=None,
            category=None,
            sub_category=None,
            due_date=None,
            custom_fields=None
    ):
        """
        Update ticket with given parameters
        @param ticket_id: Ticket ID that should be updated
        @param title: New Ticket Title
        @param description: New Ticket Description
        @param department: New Ticket Department
        @param contact: New Ticket Contact
        @param agent: New Ticket Agent
        @param team: New Ticket Team
        @param resolution: New Ticket Resolution
        @param priority: New Ticket Priority
        @param status: New Ticket Status
        @param classification: New Ticket Classification
        @param channel: New Ticket Channel
        @param category: New Ticket Category
        @param sub_category: New Ticket SubCategory
        @param due_date: New Ticket DueDate
        @param custom_fields: Zoho Ticket custom fields
        @return: None
        """
        payload = {
            "subject": title,
            "description": description,
            "departmentId": department.id if department else None,
            "contactId": contact.id if contact else None,
            "assigneeId": agent.id if agent else None,
            "teamId": team.id if team else None,
            "resolution": resolution,
            "priority": priority,
            "status": status,
            "classification": classification,
            "channel": channel,
            "category": category,
            "subCategory": sub_category,
            "dueDate": datetime.datetime.strptime(
                due_date, "%Y-%m-%dT%H:%M:%SZ"
            ).isoformat(timespec="milliseconds") + "Z" if due_date else None,
        }
        if custom_fields:
            payload.update(custom_fields)

        response = self.session.patch(
            self._get_full_url("get_ticket_details", ticket_id=ticket_id),
            json={key: value for key, value in payload.items() if value},
        )
        validate_response(response)
        return self.parser.build_ticket_object(response.json())

    def add_comment(self, ticket_id, is_public, content_type, content):
        """
        Add comment to a ticket
        :param ticket_id: {str} ticket id
        :param is_public: {bool} whether the comment should be public or private
        :param content_type: {str} type of the comment
        :param content: {str} content of the comment
        :return: {void}
        """
        url = self._get_full_url("add_comment", ticket_id=ticket_id)
        payload = {
            "isPublic": is_public,
            "contentType": content_type,
            "content": content
        }

        response = self.session.post(url, json=payload)
        validate_response(response)

    def find_department(self, name):
        """
        Find department by name
        :param name: {str} department name
        :return: {list} List of Department objects
        """
        url = self._get_full_url("get_departments")
        params = {
            "searchStr": name
        }
        response = self.session.get(url, params=params)
        validate_response(response)
        if response.content:
            return self.parser.build_results(response.json(), 'build_department_object')

    def find_contact(self):
        """
        Find contact
        :return: {list} List of Contact objects
        """
        url = self._get_full_url("get_contacts")
        params = {
            "fields": "email,id"
        }
        response = self.session.get(url, params=params)
        validate_response(response)
        if response.content:
            return self.parser.build_results(response.json(), 'build_contact_object')

    def find_product(self):
        """
        Find product
        :return: {list} List of Product objects
        """
        url = self._get_full_url("get_products")
        params = {
            "fields": "productName,id"
        }
        response = self.session.get(url, params=params)
        validate_response(response)
        if response.content:
            return self.parser.build_results(response.json(), 'build_product_object')

    def find_agent(self, name):
        """
        Find agent by name
        :param name: {str} agent name
        :return: {list} List of Agent objects
        """
        url = self._get_full_url("get_agents")
        params = {
            "searchStr": name
        }
        response = self.session.get(url, params=params)
        validate_response(response)
        if response.content:
            return self.parser.build_results(response.json(), 'build_agent_object')

    def find_team(self):
        """
        Find team
        :return: {list} List of Team objects
        """
        url = self._get_full_url("get_teams")
        response = self.session.get(url)
        validate_response(response)
        if response.content:
            return self.parser.build_results(response.json(), 'build_team_object', data_key="teams")

    def create_ticket(self, title, description, department_id, contact_id, assignee_id, team_id, channel, priority,
                      classification, category, sub_category, due_date, custom_fields):
        """
        Create a ticket
        :param title: {str} ticket title
        :param description: {str} ticket description
        :param department_id: {str} id of the department
        :param contact_id: {str} id of the contact
        :param assignee_id: {str} id of the assignee
        :param team_id: {str} id of the team
        :param channel: {str} name of the channel
        :param priority: {str} ticket priority
        :param classification: {str} ticket classification type
        :param category: {str} ticket category
        :param sub_category: {str} ticket sub category
        :param due_date: {str} due date for the ticket
        :param custom_fields: {dict} custom fields to use
        :return: {dict}
        """
        url = self._get_full_url("create_ticket")
        payload = {
            "subject": title,
            "description": description,
            "contactId": contact_id,
            "departmentId": department_id,
            "priority": priority,
            "classification": classification
        }

        if assignee_id:
            payload["assigneeId"] = assignee_id

        if team_id:
            payload["teamId"] = team_id

        if channel:
            payload["channel"] = channel

        if category:
            payload["category"] = category

        if sub_category:
            payload["subCategory"] = sub_category

        if due_date:
            payload["dueDate"] = due_date

        if custom_fields:
            payload.update(custom_fields)

        response = self.session.post(url, json=payload)
        validate_response(response)
        return self.parser.build_ticket_object(response.json())
