# ==============================================================================
# title           :ServiceNowManager.py
# description     :This Module contain all ServiceNow operations functionality
# author          :zivh@siemplify.co
# date            :01-17-18
# python_version  :3.7
# libreries       :requests
# requirments     : 
# product_version :1.0 - Jakarta
# Doc: https://developer.servicenow.com/app.do#!/rest_api_doc?v=jakarta&id=r_AggregateAPI-GET
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import requests
import json
from datetime import datetime
import urllib3
from urllib.parse import urljoin
import urllib.parse
from ServiceNowParser import ServiceNowParser
from exceptions import ServiceNowException, ServiceNowNotFoundException, ServiceNowIncidentNotFoundException, \
    ServiceNowRecordNotFoundException, ServiceNowTableNotFoundException
from constants import STATES, CLOSED, RECORD_COMMENT_TYPES


# =====================================
#             CONSTANTS               #
# =====================================
DEFAULT_TABLE = 'incident'

CREATE_TICKET_JSON = {"short_description": "<description summary>",
                      "impact": "<impact_id>",
                      "urgency": "<urgency_id>"
                      }

STATE_CLOSED = 'Closed'
DATETIME_STR_FORMAT = "%Y-%m-%d %H:%M:%S"
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

NOT_FOUND_ERROR_MSG = 'Not Found'
NOT_FOUND_STATUS = 404
CLASS_NOT_FOUND_STATUS = 400
CI_NOT_FOUND_MSG = "CI not found"

API_ENDPOINTS = {
    # Main actions
    "ping": "table/{table}",
    "create_ticket": "table/{table}",
    "update_incident": "table/{table}/{ticket}",
    "create_record": "table/{table}",
    "download-attachment": "attachment",
    "attachment_upload": "attachment/upload",
    "list_cmdb_records": "/api/now/cmdb/instance/{class_name}?sysparm_query={query_filter}&sysparm_limit={max_records_to_return}",
    "list_cmdb_records_details": "/api/now/cmdb/instance/{classname}/{sys_id}?sysparm_relation_limit={limit}",
    "get_ticket": "table/{table}/{ticket}",
    "exists_in_table": "table/{table}/{sys_id}",
    "get_incident": "table/{table}",
    "get_child_incidents": "table/incident",
    "get_record_details": "table/{table}/{sys_id}",
    "get_user_details": "table/sys_user",
    # Sub requests
    "get_group_id": "table/sys_user_group",
    "get_user_id": "table/sys_user",
    "get_ticket_id": "table/{table}",
    "get_incidents": "table/{table}",
    "get_comments": "table/sys_journal_field",
    "get_user_data": "table/sys_user",
    "get_related_data": "table/{table}",
    "get_tokens": "oauth_token.do",
    "add_comment_to_record": "table/{table_name}/{record_id}",
    "get_record_comments": "table/sys_journal_field?sysparm_query=element={type}^element_id={record_id}^name={table_name}^ORDERBYDESCsys_created_on&sysparm_limit={limit}"
}

CMDB_ACTION = "CMDB_ACTION"


# =====================================
#              CLASSES                #
# =====================================


class ServiceNowManager(object):

    def __init__(self, api_root, username, password, default_incident_table=DEFAULT_TABLE, verify_ssl=False,
                 siemplify_logger=None, client_id=None, client_secret=None, refresh_token=None, use_oauth=False):
        """
        The method is used to init an object of ServiceNowManager class
        :param api_root: API root of the server.
        :param username: Username of the account.
        :param password: Password of the account.
        :param default_incident_table: Default incident table
        :param verify_ssl: Enable (True) or disable (False). If enabled, verify the SSL certificate for the connection.
        :param siemplify_logger: Siemplify logger.
        :param client_id: Client ID of Service Now application. Required for Oauth authentication.
        :param client_secret: Client Secret of Service Now application. Required for Oauth authentication.
        :param refresh_token: Refresh token for Service Now application. Required for Oauth authentication.
        :param use_oauth: If enabled, integration will use Oauth authentication. Parameters “Client ID“, “Client Secret“
        and “Refresh Token“ are mandatory.
        """
        self.api_root = api_root
        self.username = username
        self.password = password
        self.default_incident_table = default_incident_table if default_incident_table else DEFAULT_TABLE
        self.siemplify_logger = siemplify_logger
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.use_oath = use_oauth
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers = HEADERS
        self.parser = ServiceNowParser()
        self.removed_headers = {}

        if self.use_oath:
            if not self.client_id or not self.client_secret or not self.refresh_token:
                raise ServiceNowException(u'Please specify Client ID, Client Secret and Refresh Token for OAuth '
                                          u'authentication.')
            self.session.headers.update({"Authorization": "Bearer {}".format(self.get_access_token()),
                                         "Content-Type": "application/json"})
        else:
            self.session.auth = (username, password)

    def get_access_token(self):
        """
        Get access token to use in requests.
        :return: {str} Access token.
        """
        request_url = self._get_full_url('get_tokens', general_api=True, part_to_remove='api/now/v1/')
        self.session.headers.update({"Content-Type": "application/x-www-form-urlencoded"})
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token
        }
        response = self.session.post(request_url, data=payload)
        self.validate_response(response)
        return response.json().get("access_token")

    def get_refresh_token(self):
        """
        Get refresh token to OAuth authentication.
        :return: {dict} Response json.
        """
        request_url = self._get_full_url('get_tokens', general_api=True, part_to_remove='api/now/v1/')
        self.session.headers.update({"Content-Type": "application/x-www-form-urlencoded"})
        self.session.auth = None
        payload = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password
        }
        response = self.session.post(request_url, data=payload)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 401:
                raise ServiceNowException("Invalid credentials were provided")
            raise Exception(e)
        return response.json()

    def _get_full_url(self, url_id, general_api=False, part_to_remove='v1', **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param general_api: {bool} whether to use general api or not
        :param part_to_remove: Part of url to remove, e.g v1
        :param kwargs: {dict} Variables passed for string formatting
        :return: {unicode} The full url
        """
        api_root = self.remove_version_from_apiroot(self.api_root, part_to_remove) if general_api else self.api_root
        return urljoin(api_root, API_ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity
        :return: {bool}: True if successful else raise exception
        """
        params = {
            "sysparm_limit": 1
        }
        response = self.session.get(self._get_full_url('ping', table=self.default_incident_table), params=params)
        self.validate_response(response)
        return True

    def remove_version_from_apiroot(self, api_root, version_to_remove):
        """
        Removes the version from the given root api
        :param api_root: Full Api Root given by the user
        :param version_to_remove: Version to remove, e.g v1
        :return {str}:  Api Root without the version
        """
        api_root = urllib.parse.urlparse(api_root).geturl().replace('/{}'.format(version_to_remove), '')
        return api_root

    def upload_attachment(self, table_name, record_sys_id, file_path):
        """
        Uploads the attachment to the ServiceNow
        :param table_name: Name of the table to which we upload the attachment
        :param record_sys_id: Record System ID
        :param file_path: Path to the file that should be uploaded
        :return: returns the Upload Attachment Result Object or exception
        """
        upload_attachment_url = self._get_full_url('attachment_upload', general_api=False)

        payload = {'table_name': table_name, 'table_sys_id': record_sys_id}
        files = {'file': (file_path, open(file_path, 'rb'), 'multipart/form-data', {'Expires': '0'})}

        self.session.headers.update({"Accept": "*/*"})
        self.remove_unnecessary_headers()
        response = self.session.post(upload_attachment_url, files=files, data=payload)
        self.validate_response(response)
        self.put_removed_headers_back()
        return self.parser.build_upload_file_object(response.json())

    def list_cmdb_records(self, class_name, query_filter, max_records_to_return):
        """
        Function that gets the list of CMDB Records from Service Now
        :param class_name: Name of the class in Service Now to query
        :param query_filter: Query used in the filter
        :param max_records_to_return: Maximum records to fetch
        :return: CMDB_Record Object
        """
        url = self._get_full_url('list_cmdb_records', class_name=class_name,
                                 query_filter=query_filter,
                                 max_records_to_return=max_records_to_return)

        self.session.headers.update({"Accept": "*/*"})

        response = self.session.get(url)
        self.validate_response(response)
        return self.parser.build_cmdb_record_object(response.json())

    def list_cmdb_records_details(self, class_name, sys_id, max_records_to_return):
        """
        Function that gets the list of details for CMDB Records from Service Now
        :param class_name: Name of the class in Service Now to query
        :param sys_id: Sys ID used for the request
        :param max_records_to_return: Maximum records to fetch
        :return: CMDB_Record Object
        """
        list_cmdb_records_details_url = self._get_full_url('list_cmdb_records_details', classname=class_name,
                                                           sys_id=sys_id, limit=max_records_to_return)
        # Set appropriate headers
        self.session.headers.update({"Accept": "*/*"})
        response = self.session.get(list_cmdb_records_details_url)
        self.validate_response(response)

        return self.parser.build_cmdb_record_details_object(response.json())

    def get_group_id(self, group_name):
        """
        Find group_sys_id base on on group_name
        :param group_name: {str} full group name
        :return: {str} group_id
        """
        search_params = "name={0}".format(group_name)
        response = self.session.get(self._get_full_url('get_group_id'), params={'sysparm_query': search_params})
        try:
            self.validate_response(response)
            groups = self.parser.build_results(response.json(), 'build_object')
            if groups:
                return groups[0].sys_id
        except:
            raise ServiceNowNotFoundException("Group with name {} not found".format(group_name))

    def get_user_data(self, usernames):
        """
        Find user details base on on usernames
        :param usernames: {list} user full name
        :return: {list} user model list
        """
        search_params = 'user_name={}'.format(usernames[0])
        search_params += ''.join(['^ORuser_name={}'.format(username) for username in usernames[1:]])
        request = self.session.get(self._get_full_url('get_user_data'), params={'sysparm_query': search_params})
        self.validate_response(request)

        return self.parser.build_results(request.json(), 'get_user')

    def get_user_id(self, user_name, property_string="name={}"):
        """
        Find user_sys_id base on on user_name
        :param user_name: {str} user full name
        :param property_string: {str} search param string
        :return: {str} user_id
        """
        search_params = property_string.format(user_name)
        response = self.session.get(self._get_full_url('get_user_id'), params={'sysparm_query': search_params})
        try:
            self.validate_response(response)
            users = self.parser.build_results(response.json(), 'build_object')
            if users:
                return users[0].sys_id
        except:
            raise ServiceNowNotFoundException("User with name {} not found".format(user_name))

    def get_user_related_data(self, user_id, max_records, max_days_backward, table_name=None):
        """
        Find user_sys_id base on on user_name
        :param user_id: {str} user id
        :param max_records: {int} limit of getting data
        :param max_days_backward: {int} day backward count
        :param table_name: {str} table name
        :return: {list} related records list
        """
        url = self._get_full_url('get_related_data', table=table_name)
        search_params = "opened_by={}^sys_created_onRELATIVEGT@dayofweek@ago@{}".format(user_id, max_days_backward)
        request = self.session.get(url, params={'sysparm_query': search_params, "sysparm_limit": max_records})
        self.validate_response(request)

        return self.parser.build_results(request.json(), 'get_user_related_record')

    def get_user_details_by_sys_ids(self, sys_ids):
        """
        Find user details base on on sys_id
        :param sys_ids: {list} user sys ids
        :return: {list} list of User instance
        """
        search_params = "sys_id={}".format(sys_ids[0])
        search_params += ''.join(['^ORsys_id={}'.format(sys_id) for sys_id in sys_ids[1:]])
        request = self.session.get(self._get_full_url('get_user_details'), params={'sysparm_query': search_params})
        try:
            request.raise_for_status()
        except:
            pass

        return self.parser.build_results(request.json(), 'get_user')

    def get_ticket_id(self, ticket_number, table_name=None):
        """
        Find sys_id base on on number
        :param ticket_number: {str} ticket number
        :param table_name: {str} specified table name (incident)
        :return: ticket_id {str}
        """
        table_name = table_name if table_name else self.default_incident_table
        search_params = "number={}".format(ticket_number)
        response = self.session.get(self._get_full_url('get_ticket_id', table=table_name),
                                    params={'sysparm_query': search_params})
        self.validate_response(response)
        incidents = self.parser.build_results(response.json(), 'build_incident')
        if incidents:
            return incidents[0].sys_id

        raise ServiceNowIncidentNotFoundException('Incident with number \"{}\" was not found'.format(ticket_number))

    def get_incidents(self, numbers, table_name=None, fields=None, states=None, state_match=True):
        """
        Find incidents with params
        :param numbers: {iterable} List of ticket numbers
        :param table_name: {str} specified table name (incident)
        :param fields: {list} specified record fields
        :param states: {list} specified record fields
        :param state_match: {str} matching operator = or !=
        :return: {list} List of Incident instances
        """
        table_name = self.get_table_name(table_name)
        params = {}
        sysparam_queries = []

        if numbers:
            number_query = self.__get_param_query_fragment('number', numbers, join_char='^OR')
            sysparam_queries.append(number_query)
        if states:
            operator, join_char = ('=', '^OR') if state_match else ('!=', '^')
            state_query = self.__get_param_query_fragment('state', states, operator=operator, join_char=join_char)
            sysparam_queries.append(state_query)
        if fields:
            params['sysparm_fields'] = ','.join(fields)

        params['sysparm_query'] = self.__build_system_query(sysparam_queries)
        response = self.session.get(self._get_full_url('get_incidents', table=table_name), params=params)
        self.validate_response(response)

        return self.parser.build_incidents(response.json())

    def get_incidents_with_pagination(self, numbers, table_name=None, fields=None, states=None, state_match=True,
                                      limit=100):
        """
        Find incidents with params
        :param numbers: {iterable} List of ticket numbers
        :param table_name: {str} specified table name (incident)
        :param fields: {list} specified record fields
        :param states: {list} specified record fields
        :param state_match: {str} matching operator = or !=
        :param limit: {str} limit incidents for pagination
        """
        table_name = self.get_table_name(table_name)
        params = {}
        sysparam_queries = []

        if numbers:
            number_query = self.__get_param_query_fragment('number', numbers, join_char='^OR')
            sysparam_queries.append(number_query)
        if states:
            operator, join_char = ('=', '^OR') if state_match else ('!=', '^')
            state_query = self.__get_param_query_fragment('state', states, operator=operator, join_char=join_char)
            sysparam_queries.append(state_query)
        if fields:
            params['sysparm_fields'] = ','.join(fields)

        params['sysparm_query'] = self.__build_system_query(sysparam_queries)
        params['sysparm_suppress_pagination_header'] = True

        incidents = []

        while True:
            params['sysparm_offset'] = len(incidents)
            response = self.session.get(self._get_full_url('get_incidents', table=table_name), params=params)
            self.validate_response(response)
            results = self.parser.build_incidents(response.json())

            incidents.extend(results)

            if len(results) < limit:
                break

        return incidents

    def get_ticket_comments(self, ticket_sys_ids, comments_limit=100, fields=None, table_name=None,
                            order_by=None):
        """
        Retrieve ticket comments with limit
        :param ticket_sys_ids: {str} ticket sys_id
        :param comments_limit: {int} comments per page
        :param fields: {list} specified record fields
        :param table_name: {str} specified table name (incident)
        :param order_by: {str} specified table name (incident)
        :return: {list} Incident comments {Comment}
        """
        params = {}
        sysparam_queries = []
        param_keys = ['work_notes', 'comments']

        sys_param_query = self.__get_param_query_fragment('element', param_keys, join_char='^OR')
        sysparam_queries.append(sys_param_query)

        sys_param_query = self.__get_param_query_fragment('element_id', ticket_sys_ids, join_char='^OR')
        sysparam_queries.append(sys_param_query)

        if fields:
            params['sysparm_fields'] = ','.join(fields)

        if order_by:
            sysparam_queries.append('ORDERBY{}'.format(order_by))

        params['sysparm_query'] = self.__build_system_query(sysparam_queries)
        params['sysparm_limit'] = comments_limit
        params['sysparm_suppress_pagination_header'] = True

        comments = []

        while True:
            params['sysparm_offset'] = len(comments)
            response = self.session.get(self._get_full_url('get_comments', table=table_name), params=params)
            self.validate_response(response)
            results = self.parser.build_results(response.json(), 'build_comment')

            comments.extend(results)

            if len(results) < comments_limit:
                break

        return comments

    def get_incident(self, number, table_name=None):
        """
        Find incident based on number
        :param number: {str} ticket number
        :param table_name: {str} specified table name (incident)
        :return: {Incident}
        """
        table_name = self.get_table_name(table_name)
        search_params = "number={}".format(number)
        response = self.session.get(self._get_full_url('get_incident', table=table_name),
                                    params={'sysparm_query': search_params})
        self.validate_response(response)
        incidents = self.parser.build_results(response.json(), 'build_incident')
        return incidents[0] if incidents else None

    def get_child_incidents(self, sys_id, max_records):
        """
        Find child incidents based on incident sys id
        :param sys_id: {str} incident sys_id
        :param max_records: {int} max limit
        :return: {list} list of ChildIncidents instance
        """
        search_params = "parent_incident={}".format(sys_id)
        response = self.session.get(self._get_full_url('get_child_incidents'),
                                    params={'sysparm_query': search_params, 'sysparm_limit': max_records})
        self.validate_response(response)

        return self.parser.build_results(response.json(), 'get_child_incident')

    def create_object(self, json_data=None, table_name=None):
        """
        Retrieve object details and create new object in specific table in ServiceNow.
        :param json_data: {dict} object details ('Column name': value}
        :param table_name: {str} table name in serviceNow ("incident")
        :return: {ServiceNowObject, list} Created object, not processed fields
        """
        table_name = self.get_table_name(table_name)
        if json_data:
            json_data_keys = list(json_data.keys())
            # Convert names to ids
            if "assignment_group" in json_data_keys:
                json_data["assignment_group"] = self.get_group_id(json_data["assignment_group"])
            if "assigned_to" in json_data_keys:
                json_data["assigned_to"] = self.get_user_id(json_data["assigned_to"])

        response = self.session.post(self._get_full_url('create_record', table=table_name), json=json_data)
        # Indicates the request completed successfully.
        self.validate_response(response)
        service_now_object = self.parser.build_result(response.json(), 'build_object')
        service_now_object_json = service_now_object.to_json()
        not_used_custom_keys = []

        for key, value in json_data.items():
            if key not in service_now_object_json or (key in service_now_object_json and service_now_object_json.get(key) != value):
                if key not in ['assignment_group', 'assigned_to']:
                    not_used_custom_keys.append(key)

        return service_now_object, not_used_custom_keys

    def create_ticket(self, short_description, impact, urgency, table_name=None, category=None, assignment_group=None,
                      assigned_to=None, description=None, custom_fields=None):
        """
        Retrieve ticket details and create new incident in ServiceNow. (Short description + caller are mandatory params).
        :param short_description: {str}
        :param impact: {int} 1-High, 2-Medium, 3-Low
        :param urgency: {int} 1-High, 2-Medium, 3-Low
        :param category: {str} (Help, Database, Network, software, hardware)
        :param table_name: {str} table name
        :param assignment_group: {str} assignment group full name
        :param assigned_to: {str} assigned user full name (first last)
        :param description: {str}
        :param custom_fields: {dict} custom fields
        :return: {Ticket, list} Create ticket, list of not updated fields
        """
        # Create json with desire incident properties
        table_name = table_name if table_name else self.default_incident_table
        json_data = CREATE_TICKET_JSON
        json_data["short_description"] = short_description

        user = self.get_user_id(user_name=self.username, property_string="user_name={}")
        json_data["caller_id"] = user
        json_data["impact"] = impact
        json_data["urgency"] = urgency

        if category:
            json_data["category"] = category
        if assignment_group:
            assignment_group_id = self.get_group_id(assignment_group)
            json_data["assignment_group"] = assignment_group_id
        if assigned_to:
            assign_user_id = self.get_user_id(assigned_to)
            json_data["assigned_to"] = assign_user_id
        if description:
            json_data["description"] = description

        if custom_fields:
            json_data.update(custom_fields)

        response = self.session.post(self._get_full_url('create_ticket', table=table_name), json=json_data)
        # Indicates the request completed successfully.
        self.validate_response(response)
        ticket = self.parser.build_result(response.json(), 'build_ticket')
        not_used_custom_keys = []
        if custom_fields:
            for key in custom_fields:
                if key not in ticket.to_json():
                    if key not in ['assigned_to', 'assignment_group']:
                        not_used_custom_keys.append(key)

        return ticket, not_used_custom_keys

    def get_ticket(self, ticket_number, table_name=None):
        """
        Retrieve ticket number and get incident details in ServiceNow
        :param ticket_number: {str}
        :param table_name: {str}
        :return: {dict} Incident details
        """
        # Get ticket sys_id base on ticket number
        table_name = self.get_table_name(table_name)
        ticket_id = self.get_ticket_id(ticket_number, table_name)
        url = self._get_full_url('get_ticket', table=table_name, ticket=ticket_id)
        response = self.session.get(url, params={'sysparm_display_value': True})
        self.validate_response(response)
        ticket = self.parser.build_result(response.json(), 'build_ticket')
        return ticket

    def get_table_name(self, table_name=None):
        """
        Get table name
        :param table_name: {str}
        :return: {str} Table name
        """
        return table_name if table_name else self.default_incident_table

    def get_ticket_by_id(self, ticket_id, table_name=None):
        """
        Retrieve ticket id and get incident details  in ServiceNow
        :param ticket_id: {str}
        :param table_name: {str}
        :return: {dict} Incident details
        """
        url = self._get_full_url('get_ticket', table=self.get_table_name(table_name), ticket=str(ticket_id))
        response = self.session.get(url)
        self.validate_response(response)
        return self.parser.build_result(response.json(), 'build_ticket')

    def get_record_details(self, ticket_sys_id, fields, table_name=None):
        """
        Gets the Record details
        :param ticket_sys_id: {str} Record Sys ID
        :param fields: {list} specified record fields
        :param table_name: {str} table name in serviceNow ("incident")
        :return: {RecordDetail} instance
        """
        table_name = self.get_table_name(table_name)
        url = self._get_full_url('get_record_details', table=table_name, sys_id=ticket_sys_id)
        params = {'sysparm_fields': "{}".format(','.join(fields))} if fields else {}
        response = self.session.get(url, params=params)
        self.validate_response(response)

        return self.parser.build_result(response.json(), 'build_record_detail')

    def get_incident_properties(self, ticket_number, table_name=None):
        """
        Retrieve incident id and get get his properties in ServiceNow
        :param ticket_number: {str}
        :param table_name: {str}
        :return: {list} Incident properties
        """
        table_name = self.get_table_name(table_name)
        ticket = self.get_ticket(ticket_number, table_name)
        incident_properties = list(ticket.keys())
        return incident_properties

    def update_object(self, json_data, ticket_sys_id, table_name=None):
        """
        Retrieve object details and update record in specific table in ServiceNow.
        :param json_data: {dict} object details ('Column name': value}
        if column does not exist, the requests still not failed
        :param ticket_sys_id: {str} object sys id
        :param table_name: {str} table name in serviceNow ("incident")
        :return: {Ticket} Updated ticket
        """
        # Get ticket
        table_name = self.get_table_name(table_name)
        ticket_json = self.get_ticket_by_id(ticket_sys_id, table_name=table_name).to_json()
        ticket_json.update(json_data)
        url = self._get_full_url('get_ticket', table=table_name, ticket=ticket_sys_id)
        response = self.session.put(url, json=ticket_json)
        self.validate_response(response)

        return self.parser.build_result(response.json(), 'build_ticket')

    def update_incident(self, ticket_number, table_name=None, short_description=None, impact=None, urgency=None,
                        category=None, assignment_group=None, assigned_to=None, comments=None,
                        description=None, incident_state=None, close_notes=None, close_code=None, custom_fields=None,
                        work_notes=None):
        """
        Inserts one record in the specified table.
        :param ticket_number: {str}
        :param table_name: {str}
        :param short_description: {str}
        :param impact: {int} 1-High, 2-Medium, 3-Low
        :param urgency: {int} 1-High, 2-Medium, 3-Low
        :param category: {str} (Help, Database, Network, software, hardware)
        :param assignment_group: {str} assignment_group full name
        :param assigned_to: {str} assigned user full name (first last)
        :param comments: {str}
        :param description: {str}
        :param incident_state: {STATES} status name or status id
        :param close_notes: {str} notes for closing incident
        :param close_code: {str} incident resolution code
        :param custom_fields: {dict} custom fields
        :param work_notes: {str}
        :return: {Ticket, list} Updated ticket, list of not updated fields
        """
        # Check which fields the user want to update.
        table_name = self.get_table_name(table_name)
        update_payload = {}
        if short_description:
            update_payload["short_description"] = short_description
        if impact:
            update_payload["impact"] = impact
        if urgency:
            update_payload["urgency"] = urgency
        if category:
            update_payload["category"] = category
        if assignment_group:
            assignment_group_id = self.get_group_id(assignment_group)
            update_payload["assignment_group"] = assignment_group_id
        if assigned_to:
            assign_user_id = self.get_user_id(assigned_to)
            update_payload["assigned_to"] = assign_user_id
        if comments:
            update_payload["comments"] = comments
        if description:
            update_payload["description"] = description
        if incident_state:
            update_payload["state"] = incident_state
        if close_notes:
            update_payload["close_notes"] = close_notes
        if close_code:
            update_payload["close_code"] = close_code
        if work_notes:
            update_payload["work_notes"] = work_notes

        if custom_fields:
            update_payload.update(custom_fields)
        # Get ticket sys_id base on ticket number
        ticket_id = self.get_ticket_id(ticket_number, table_name)
        url = self._get_full_url('update_incident', table=table_name, ticket=ticket_id)
        response = self.session.put(url, json=update_payload)
        self.validate_response(response)
        ticket = self.parser.build_result(response.json(), 'build_ticket')
        updated_ticket_json = ticket.to_json()
        not_used_custom_keys = []
        # Check if data successfully updated
        # API returns status_code 200 even if the field not successfully updated.
        for key in list(update_payload.keys()):
            if key in ['comments', 'state', 'work_notes']:
                continue
            if key in ['assigned_to', 'assignment_group']:
                if update_payload[key] != updated_ticket_json[key]['value']:
                    raise ServiceNowException(
                        "Could not update {0} with value: {1}.".format(key, update_payload[key]))
                continue
            if key in updated_ticket_json and update_payload[key] != updated_ticket_json[key]:
                raise ServiceNowException("Could not update {0} with value: {1}.".format(key, updated_ticket_json[key]))
            if key not in updated_ticket_json and key in custom_fields:
                not_used_custom_keys.append(key)

        return ticket, not_used_custom_keys

    def close_incident(self, ticket_number, close_reason, close_notes=None, close_code=None):
        """
        Retrieve incident sys_id and change state to close
        Note: state are different from table object to another
        :param ticket_number: {str}
        :param close_reason: {str}
        :param close_notes: {str} notes for closing incident
        :param close_code: {str} incident resolution code
        :return: {str} incident_id if updated, else none.
        """
        incident_number, not_used_fields = self.update_incident(ticket_number, incident_state=STATES[CLOSED],
                                                                comments=close_reason, close_notes=close_notes,
                                                                close_code=close_code)
        return incident_number

    def add_comment_to_incident(self, ticket_number, comment, table_name=None):
        """
        Retrieve incident sys_id and add comment to incident
        :param ticket_number: {str}
        :param comment: {str}
        :param table_name: {str}
        :return: {str} incident_id if updated, else none.
        """
        incident_number, not_used_fields = self.update_incident(ticket_number, comments=comment,
                                                                table_name=self.get_table_name(table_name))
        return incident_number

    def add_work_note_to_incident(self, ticket_number, work_note, table_name=None):
        """
        Retrieve incident sys_id and add work note to incident
        :param ticket_number: {str}
        :param work_note: {str}
        :param table_name: {str}
        :return: {str} incident_id if updated, else none.
        """
        incident_number, not_used_fields = self.update_incident(ticket_number, work_notes=work_note,
                                                                table_name=self.get_table_name(table_name))
        return incident_number

    def get_domain_id_by_name(self, domain_name):
        """
        Find domain sys_id base on on domain name
        :param domain_name: {str} Domain name
        :return: domain_id {str}
        """
        search_params = "name={0}".format(domain_name)
        url = self.api_root + 'table/domain'
        res = self.session.get(url, params={'sysparm_query': search_params})
        try:
            res.raise_for_status()
        except Exception as error:
            raise ServiceNowException("Error: {0} {1}".format(error, res.text))

        domain = res.json()
        return domain['result'][0]['sys_id']

    def get_incidents_by_filter(self, creation_time=None, domain=None, close_status=None, updated_time=None,
                                table_name=None, custom_queries=None):
        """
        Get incidents by filter.
        :param creation_time: {str} '2018-06-27 11:46:09' in utc time
        :param updated_time: {str} '2018-06-27 11:46:09' in utc time
        :param domain: {str} Domain name
        :param close_status: {str} number of the state ('7' = closed)
        :param table_name: {str}
        :param custom_queries: {list} of custom query strings
        :return: {list} of incidents {dict}
        """
        search_params = ""
        if domain:
            # Convert domain name to domain sys id
            domain_id = self.get_domain_id_by_name(domain)
            search_params = "sys_domain={0}".format(domain_id)
        if updated_time:
            search_params = "active=true^sys_updated_on>{0}".format(updated_time)
        if creation_time:
            search_params = "active=true^sys_created_on>{0}".format(creation_time)
        if close_status:
            search_params = "active=false^state={0}^sys_updated_on>{1}".format(close_status, updated_time)
        if custom_queries:
            if search_params:
                search_params = search_params + '^'
            search_params += '^'.join(custom_queries)

        url = self._get_full_url('get_incidents', table=self.get_table_name(table_name))
        response = self.session.get(url, params={'sysparm_query': search_params})
        self.validate_response(response)

        return self.parser.build_incidents(response.json())

    def get_additional_context_for_field(self, link):
        """
        Get additional context for incident field
        :param link: {str} The request url
        :return: {dict} Result JSON
        """
        response = self.session.get(link)
        self.validate_response(response)

        return response.json().get("result", {})

    def get_user_info(self, opener_id, caller_id):
        """
        Get user info by incident sys_id and incident opener id.
        :param opener_id {str} incident opener id
        :param caller_id: {str} incident caller id
        :return: {list} List of User instance
        """
        search_params = 'sys_id={}^ORsys_id={}'.format(opener_id, caller_id)
        url = self._get_full_url('get_user_id')
        response = self.session.get(url, params={'sysparm_query': search_params})
        self.validate_response(response)

        return self.parser.build_users_data(response.json())

    def get_full_domain_name_by_id(self, domain_id):
        """
        Find full domain base on on domain id
        :param domain_id: {str} Domain sys id
        :return: full domain {str} 'TOP/Cisco/Ziv...'
        """
        res = self.session.get('{0}{1}/{2}'.format(self.api_root, 'table/domain', domain_id))
        try:
            res.raise_for_status()
        except Exception as error:
            raise ServiceNowException("Error: {0} {1}".format(error, res.text))

        sub_domain = res.json()['result']
        is_primary = sub_domain['primary']
        full_domain = sub_domain['name']

        while is_primary == 'false':
            parent_res = self.session.get(sub_domain['parent']['link'])
            try:
                parent_res.raise_for_status()
            except Exception as error:
                raise ServiceNowException("Error: {0} {1}".format(error, parent_res.text))
            sub_domain = parent_res.json()['result']
            is_primary = parent_res.json()['result']['primary']
            full_domain = '{0}/{1}'.format(parent_res.json()['result']['name'], full_domain)

        return full_domain

    def get_incident_comments(self, ticket_number, table_name=None):
        """
        Retrieve ticket number and get incident comments in ServiceNow
        :param ticket_number: {str} Incident number
        :param table_name: {str} table name
        :return: {list} Incident comments {Comment}
        """
        # Get ticket sys_id base on ticket number
        ticket_id = self.get_ticket_id(ticket_number, table_name=self.get_table_name(table_name))

        search_params = "element=comments^element_id={0}".format(ticket_id)
        response = self.session.get(self._get_full_url('get_comments'), params={'sysparm_query': search_params})
        self.validate_response(response)
        return self.parser.build_results(response.json(), 'build_comment')

    def create_object_in_table(self, table_name=None, **kwargs):
        """
        Retrieve object details and keys and create new object in ServiceNow specific table.
        :param table_name: {str} specified table name (incident)
        :param kwargs: fields names and values
        :return: {str} object number
        """
        table_name = table_name if table_name else self.default_incident_table
        json_data = kwargs

        # Convert names to ids
        if "assignment_group" in list(kwargs.keys()):
            assignment_group_id = self.get_group_id(kwargs["assignment_group"])
            json_data["assignment_group"] = assignment_group_id
        if "assigned_to" in list(kwargs.keys()):
            assign_user_id = self.get_user_id(kwargs["assigned_to"])
            json_data["assigned_to"] = assign_user_id

        url = '{0}table/{1}'.format(self.api_root, table_name)
        create_request = self.session.post(url, json=json_data)

        try:
            create_request.raise_for_status()
        except Exception as error:
            raise ServiceNowException("Error: {0} {1}".format(error, create_request.text))

        result = create_request.json()
        object_number = result['result']['number']
        return object_number

    def is_exists_in_table(self, table_name, sys_id):
        """
        Check is sys_id exists in table
        :param table_name: {str} specified table name (incident)
        :param sys_id: {str} sys_id for given record
        :return: {bool}
        """
        response = self.session.get(self._get_full_url('exists_in_table', table=table_name, sys_id=sys_id))
        self.validate_response(response)

        return True

    def get_attachments_info(self, table_name, sys_id, download_folder_path):
        """
        Get attachments downloading info
        :param table_name: {str} specified table name (incident)
        :param sys_id: {str} sys_id for given record
        :param download_folder_path: {str} path where have to be downloaded the files
        :return: {list} attachment object list
        """
        search_params = "table_name={}^table_sys_id={}".format(table_name, sys_id)
        response = self.session.get(self._get_full_url('download-attachment'), params={'sysparm_query': search_params})
        self.validate_response(response)

        return self.parser.build_attachments_object(response.json(), download_folder_path)

    def get_attachment_content(self, download_link):
        """
        Get attachments downloading info
        :param download_link: {str} attachment download link
        :return: {bytes} attachment content
        """
        request = self.session.get(url=download_link)
        try:
            request.raise_for_status()
        except Exception as e:
            raise ServiceNowException("An error occurred. ERROR: {0}. {1}".format(e, request.content))

        return request.content

    @classmethod
    def check_and_raise_not_found_exceptions(cls, exception):
        """
        Raise exception if exception is not found exception
        :param exception: {Exception} The api error
        """
        error_message = cls.get_api_error_message(exception) or exception.response.content.decode()

        if 'Invalid table' in error_message:
            raise ServiceNowTableNotFoundException(error_message)
        if exception.response.status_code == NOT_FOUND_STATUS:
            raise ServiceNowRecordNotFoundException(error_message)
        if exception.response.status_code == CLASS_NOT_FOUND_STATUS:
            raise ServiceNowNotFoundException(error_message)

    @classmethod
    def get_api_error_message(cls, exception):
        """
        Get API error message
        :param exception: {Exception} The api error
        :return: {str} error message
        """
        try:
            response_json = json.loads(exception.response.content)
            return response_json.get('error', {}).get('message')
        except:
            return None

    @classmethod
    def validate_response(cls, response, error_msg='An error occurred', force_json_result=True):
        """
        Validate response
        :param response: {requests.Response} The response to validate
        :param error_msg: {str} Default message to display on error
        :param force_json_result: {bool} If True raise exception if result is not json
        """
        try:
            response.raise_for_status()
            if force_json_result:
                response.json()

        except requests.HTTPError as error:
            cls.check_and_raise_not_found_exceptions(error)
            clean_error_message = cls.get_api_error_message(error)
            if clean_error_message:
                raise Exception(clean_error_message)
            raise Exception(
                '{error_msg}: {error} {text}'.format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

        return True

    @staticmethod
    def convert_datetime_to_sn_format(datetime_obj):
        """
        Convert Datetime object to ServiceNow Datetime format
        :param datetime_obj: {datetime} convert datetime object to ServiceNow timestamp string.
        :return: {str} ServiceNow datetime format
        """
        return datetime.strftime(datetime_obj, DATETIME_STR_FORMAT)

    @staticmethod
    def __build_system_query(query_fragments, join_char='^'):
        """
        Join query fragments
        :param query_fragments {list}
        :param join_char {str} char for join fragments
        :return: {str} query string
        """
        return join_char.join(query_fragments)

    @staticmethod
    def __get_param_query_fragment(key, values, operator='=', join_char='^'):
        """
        Generate query fragment
        :param key {str} query key
        :param values {list} List of query values
        :param operator {str} operator between key nad value
        :param join_char {str} char for join fragment
        """
        return join_char.join(['{}{}{}'.format(key, operator, fragment) for fragment in values])

    def remove_unnecessary_headers(self):
        """
        Remove unnecessary headers. For example we need to remove content type for upload_attachment action
        """
        self.removed_headers = {}
        headers_to_remove = ['Content-Type']
        for header in headers_to_remove:
            self.removed_headers[header] = self.session.headers.get(header)
            del self.session.headers[header]

    def put_removed_headers_back(self):
        """
        Put removed headers back. This is important to call after remove_unnecessary_headers in order to make other
        manager's actions work regardless of other actions(ex upload_attachment action)
        """
        self.session.headers.update(self.removed_headers)

    def add_comment_to_record(self, table_name, type, record_id, text):
        """
        Add comment/work note to record
        :param table_name {str} Table name
        :param type {str} Specifies if comment or work note should be added to the record
        :param record_id {str} Record ID
        :param text {str} Content of the comment or work note
        :return: {void}
        """
        request_url = self._get_full_url('add_comment_to_record', table_name=table_name, record_id=record_id)

        payload = {
            RECORD_COMMENT_TYPES.get(type): text
        }

        response = self.session.put(request_url, json=payload)
        self.validate_response(response)

    def get_record_comments(self, table_name, type, record_id, limit=None):
        """
        Get record comments/work notes
        :param table_name {str} Table name
        :param type {str} Specifies if comments or work notes should be fetched
        :param record_id {str} Record ID
        :param limit: {int} Results limit
        :return: {list} List of Comment objects
        """
        request_url = self._get_full_url('get_record_comments', table_name=table_name, record_id=record_id,
                                         type=RECORD_COMMENT_TYPES.get(type), limit=limit if limit else 100)
        response = self.session.get(request_url)
        self.validate_response(response)
        return self.parser.build_comment_objects(response.json())
