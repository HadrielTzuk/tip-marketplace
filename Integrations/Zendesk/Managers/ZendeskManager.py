# ==============================================================================
# title           :ZendeskManager.py
# description     :This Module contain all Zendesk operations functionality
# author          :zdemoniac@gmail.com
# date            :07-02-18
# python_version  :2.7
# libraries       :
# requirements    :
# product_version : v2 API
# Doc             : https://developer.zendesk.com/rest_api/docs/core/introduction#the-api
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import base64
import requests
# =====================================
#             CONSTANTS               #
# =====================================
BASE_URL = '{0}/api/v2'
HEADERS = {'Content-Type': 'application/json', "Accept": "application/json"}

NOT_FOUND_ERROR = 'Not found'
# =====================================
#              CLASSES                #
# =====================================


class ZendeskManagerError(Exception):
    """
    General Exception for Zendesk manager
    """
    pass


class ZendeskManager(object):
    """
    Responsible for all Zendesk system operations functionality
    This API is rate limited. Allow a certain number of requests per minute depending on user plan and the endpoint.
    """
    def __init__(self, email, api_token, server_address):
        self.url = BASE_URL.format(server_address)

        self.session = requests.session()
        # This is an SSL-only API
        self.session.verify = True
        self.session.headers = HEADERS
        # Create token and insert it to the header.
        self.session.headers.update({"Authorization": "Basic {0}".format(base64.b64encode(
            "{email_address}/token:{api_token}".format(email_address=email, api_token=api_token)))})

    def test_connectivity(self):
        """
        Validates connectivity
        :return: {boolean} True/False
        """
        tickets = self.get_tickets()
        if tickets:
            return True
        return False

    def get_tickets(self):
        """
        Get a list of all tickets
        :return: {dict} include {list} with all tickets {dicts}
        """
        # Returns a maximum of 100 tickets per page.
        # Tickets are ordered chronologically by created date, from oldest to newest.
        url = '{0}/{1}.json'.format(self.url, 'tickets')
        r = self.session.get(url)
        return self.validate_response(r)

    def get_ticket_details(self, ticket_id):
        """
        Get ticket details
        :param ticket_id: {string}
        :return: {dict} include dict with the ticket properties though not the ticket comments.
        """
        url = '{0}/{1}/{2}.json'.format(self.url, 'tickets', ticket_id)
        r = self.session.get(url)
        return self.validate_response(r)

    def get_user_id_by_name(self, user_name):
        """
        Retrieve user id
        :param user_name: {string} user full name (Case sensitive)
        :return: {long} user id
        """
        url = '{0}/users.json'.format(self.url)
        users_list = self.session.get(url)
        users_list = self.validate_response(users_list)
        if users_list:
            for user in users_list['users']:
                if user['name'] == user_name:
                    return user['id']
        raise ZendeskManagerError("User {0} does not exist in Zendesk.".format(user_name))

    def get_group_id_by_name(self, group_name):
        """
        Retrieve group id
        :param group_name: {string} group name (Case sensitive)
        :return: {long} group id
        """
        url = '{0}/groups.json'.format(self.url)
        groups_list = self.session.get(url)
        groups_list = self.validate_response(groups_list)
        if groups_list:
            for group in groups_list['groups']:
                if group['name'] == group_name:
                    return group['id']
        raise ZendeskManagerError("Group {0} does not exist in Zendesk.".format(group_name))

    def get_users_email_addresses(self):
        """
        Get all users email addresses
        :return:
        """
        url = '{0}/users.json'.format(self.url)
        params = {
            "page[size]": 100
        }
        response = self.session.get(url, params=params)
        json_response = self.validate_response(response)
        users = json_response.get("users", [])
        has_more = json_response.get("meta", {}). get("has_more", False)
        cursor = json_response.get("meta", {}).get("after_cursor", "")

        while has_more:
            params.update({
                "page[after]": cursor
            })

            response = self.session.get(url, params=params)
            json_response = self.validate_response(response)
            has_more = json_response.get("meta", {}).get("has_more", False)
            cursor = json_response.get("meta", {}).get("after_cursor", "")
            users.extend(json_response.get("users", []))

        return [user['email'] for user in users] if users else []

    def create_ticket(self, subject, description, assigned_to=None, assignment_group=None, priority=None,
                      ticket_type=None, tags=None, internal_note=None, email_ccs=None):
        """
        Create a "ticket" object that specifies the ticket properties.
        :param subject: {string} The subject of the ticket
        :param description: {string} The initial comment
        :param assigned_to: {string} user full name
        :param assignment_group: {string} group name
        :param priority: {string} Allowed values are urgent, high, normal, or low
        :param ticket_type: {string} Allowed values are problem, incident, question, or task
        :param tags: {array} An array of tags to add to the ticket.
        :param email_ccs: {list} A list of emails to send the notification to.
        :return: {dict} include a ticket object {dict} and an audit object with an events array that lists all the updates made to the new ticket.
        """
        url = '{0}/{1}.json'.format(self.url, 'tickets')

        # The only required property is "comment".
        ticket_data = {
            "ticket": {
                "subject": subject,
                "comment": {"body": description},
                "status": 'open'}
        }

        if assigned_to:
            # Convert to the numeric ID of the agent to assign the ticket to.
            assigne_id = self.get_user_id_by_name(assigned_to)
            ticket_data['ticket']['assignee_id'] = assigne_id

        if assignment_group:
            # Convert to the numeric ID of the agent to assign the ticket to.
            group_id = self.get_group_id_by_name(assignment_group)
            ticket_data['ticket']['group_id'] = group_id

        if priority:
            ticket_data['ticket']['priority'] = priority

        if ticket_type:
            ticket_data['ticket']['type'] = ticket_type

        if tags:
            ticket_data['ticket']['tags'] = tags
            
        if not internal_note:
            ticket_data['ticket']['comment']['public'] = internal_note

        if email_ccs:
            ticket_data['ticket']['email_ccs'] = []
            for email in email_ccs:
                ticket_data['ticket']['email_ccs'].append({
                    "user_email": email,
                    "action": "put"
                })

        r = self.session.post(url, json=ticket_data)
        return self.validate_response(r)

    def get_ticket_tags(self, ticket_id):
        """
        Get tickets that belong to specific ticket
        :param ticket_id: {sting} ticket number
        :return: {list} ticket tags
        """
        url = '{0}/{1}/{2}/{3}.json'.format(self.url, 'tickets', ticket_id, 'tags')
        r = self.session.get(url)
        return self.validate_response(r)['tags']

    def update_ticket(self, ticket_id, subject=None, assigned_to=None,
                      assignment_group=None, priority=None, ticket_type=None,
                      tag=None, status=None):
        """
        Update  existing ticket details
        :param ticket_id: {string} ticket number
        :param subject: {string} The subject of the ticket
        :param assigned_to: {string} user full name
        :param assignment_group: {string} group name
        :param priority: {string} Allowed values are urgent, high, normal, or low
        :param ticket_type: {string} Allowed values are problem, incident, question, or task
        :param tag: {string} tag to add to the ticket.
        :param status: {string} The state of the ticket. Possible values: "new", "open", "pending", "hold", "solved", "closed"
        :return: {dict} include a ticket object {dict} and an audit object with an events array that lists all the updates {dict}.
        """
        # The PUT request takes one parameter, a ticket object
        ticket_data = self.get_ticket_details(ticket_id)

        if ticket_data:

            if subject:
                ticket_data['ticket']['raw_subject'] = subject

            if assigned_to:
                # Convert to the numeric ID of the agent to assign the ticket to.
                assigne_id = self.get_user_id_by_name(assigned_to)
                ticket_data['ticket']['assignee_id'] = assigne_id

            if assignment_group:
                # Convert to the numeric ID of the agent to assign the ticket to.
                group_id = self.get_group_id_by_name(assignment_group)
                ticket_data['ticket']['group_id'] = group_id

            if priority:
                ticket_data['ticket']['priority'] = priority

            if ticket_type:
                ticket_data['ticket']['type'] = ticket_type

            if tag:
                tags = self.get_ticket_tags(ticket_id)
                tags.append(tag)
                ticket_data['ticket']['tags'] = tags

            if status:
                ticket_data['ticket']['status'] = status

            url = '{0}/{1}/{2}.json'.format(self.url, 'tickets', ticket_id)
            r = self.session.put(url, json=ticket_data)
            return self.validate_response(r)

        return None

    def get_agents(self):
        """
        Get list of all agents (Include admin users)
        :return: {dict} include {list} with all agents (each agent is a dict}
        """
        # Administrators have all the abilities of agents
        url = '{0}/users.json'.format(self.url)
        agents_list = self.session.get(url, params={'role[]': ['agent', 'admin']})
        return self.validate_response(agents_list)

    def get_ticket_comments(self, ticket_id):
        """
        Ticket comments represent the conversation between requesters, collaborators, and agents.
        :param ticket_id: {sting} ticket number
        :return: {list} All comments {dict}
        """
        url = '{0}/{1}/{2}/{3}.json'.format(self.url, 'tickets', ticket_id, 'comments')
        r = self.session.get(url)
        return self.validate_response(r)['comments']

    def add_comment_to_ticket(self, ticket_id, comment_body=None, author_name=None, internal_note=True):
        """
        Add comment to ticket
        Ticket comments represent the conversation between requesters, collaborators, and agents. Comments can be public or private.
        :param ticket_id: {sting} ticket number
        :param comment_body: {string} the comment to add to the conversation
        :param author_name: {sting} The full name of the comment author.
        :param internal_note: {boolean} true if a public comment; false if an internal note.
        :return: {dict} include a ticket object {dict} and an audit object with an events array that lists all the updates {dict}.
        """
        # The PUT request takes one parameter, a ticket object
        ticket_data = self.get_ticket_details(ticket_id)

        if ticket_data:
            # Add comment field - Ticket comments are represented as JSON objects
            ticket_data['ticket'].update({'comment': {}})

            if comment_body:
                ticket_data['ticket']['comment']['body'] = comment_body

            if author_name:
                # Convert to the numeric ID of the comment author.
                author_id = self.get_user_id_by_name(author_name)
                ticket_data['ticket']['comment']['author_id'] = author_id

            if not internal_note:
                ticket_data['ticket']['comment']['public'] = internal_note

            url = '{0}/{1}/{2}.json'.format(self.url, 'tickets', ticket_id)
            r = self.session.put(url, json=ticket_data)
            return self.validate_response(r)

        raise ZendeskManagerError("Failed to add comment to ticket with ID: {0}.".format(ticket_id))

    def get_attachments_from_ticket(self, ticket_id):
        """
        Get attachments from ticket
        :param ticket_id: {string} ticket number
        :return: {list} of dicts (file name: file content)
        """
        # Get ticket details
        ticket_comments = self.session.get('{0}/tickets/{1}/comments.json'.format(self.url, ticket_id)).json()
        attachments = []
        if ticket_comments:
            for comment in ticket_comments['comments']:
                if comment['attachments']:
                    for attachment in comment['attachments']:
                        file_content = self.session.get(attachment['content_url']).content
                        attachments.append({attachment['file_name']: file_content})
        return attachments

    def search_tickets(self, query):
        """
        Search ticket using filters
        :param query: {string} a search string. For example: 'type:ticket status:pending'
        :return: {dict} Queries are represented as JSON
        """
        url = '{0}/{1}.json'.format(self.url, 'search')
        r = self.session.get(url, params={'query': query})
        return self.validate_response(r)

    def get_macro_id_by_name(self, macro_name):
        """
        Get macro id by macro title
        :param macro_name: {string} macro title (Case sensitive)
        :return: {String} macro id
        """
        url = '{0}/macros.json'.format(self.url)
        r = self.session.get(url)
        macros = self.validate_response(r).get('macros')
        if macros:
            for macro in macros:
                if macro_name == macro['title']:
                    return str(macro['id'])
        raise ZendeskManagerError('{0} Macro does not exist.'.format(macro_name))

    def apply_macro_on_ticket(self, ticket_id, macro_title):
        """
        Aplly macro on specific ticket
        :param ticket_id:
        :param macro_title:
        :return: full ticket object as it would be after applying the macro to the ticket.
        """
        # Get macro id by macro name
        macro_id = self.get_macro_id_by_name(macro_title)
        if macro_id:
            url = '{0}/{1}/{2}/{3}/{4}/apply.json'.format(self.url, 'tickets', ticket_id, 'macros', macro_id)
            r = self.session.get(url)
            ticket_new_data = self.validate_response(r)

            # Update ticket with the response data because this request doesn't actually change the ticket.
            url = '{0}/{1}/{2}.json'.format(self.url, 'tickets', ticket_id)
            res = self.session.put(url, json=ticket_new_data['result'])
            return self.validate_response(res)
        raise ZendeskManagerError('{0} Macro does not exist.'.format(macro_title))

    @staticmethod
    def validate_response(response):
        """
        Validate an HTTP response.
        :param response: HTTP response object {HTTP response}
        :return: exception thrown in case the response is not valid {void}
        """
        try:
            if NOT_FOUND_ERROR in response.content and response.status_code == 404:
                return
            response.raise_for_status()
        except requests.HTTPError as err:
            raise ZendeskManagerError('HTTP Error: {0}'.format(err.message))
        return response.json()
