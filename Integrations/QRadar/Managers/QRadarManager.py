import requests
import json
import copy
import datetime
import operator
import time
from requests.exceptions import ConnectionError
import urllib.request
import urllib.parse
import urllib.error
from functools import reduce
from exceptions import QRadarApiError, QRadarRequestError, QRadarNotFoundError, QRadarValidationError, \
    QRadarCustomFieldValidation
from QRadarParser import QRadarParser
from SiemplifyDataModel import EntityTypes
from constants import EVENTS_DATA_TYPE_IDENTIFIER, FLOWS_DATA_TYPE_IDENTIFIER, OFFENSES_STATUS_OPEN, \
    SIEMPLIFY_CLOSE_REASON, INVALID_AQL_ERROR
from urllib.parse import urljoin
from TIPCommon import string_to_multi_value


# CONSTANTS
SPACE = ' '

API_ENDPOINTS = {
    'get_search_status_url': 'api/ariel/searches/{search_id}',
    'get_search_results_url': 'api/ariel/searches/{search_id}/results',
    'run_query': 'api/ariel/searches?query_expression={query}',
    'offenses': 'api/siem/offenses',
    'rules': 'api/analytics/rules',
    'close_reason_url': 'api/siem/offense_closing_reasons',
    'offense_url': 'api/siem/offenses/{offense_id}',
    'reference_set': 'api/reference_data/sets/{set_name}',
    'add_offense_note': '/api/siem/offenses/{offense_id}/notes',
    'map_of_sets': 'api/reference_data/map_of_sets',
    'maps': '/api/reference_data/maps',
    'reference_map': 'api/reference_data/maps/{map_name}',
    'sets': '/api/reference_data/sets',
    'reference_map_of_sets': 'api/reference_data/map_of_sets/{map_name}',
    'tables': 'api/reference_data/tables',
    'sets': '/api/reference_data/sets',
    'reference_table': 'api/reference_data/tables/{table_name}',
    'reference_map_of_sets': 'api/reference_data/map_of_sets/{map_name}',
    'sets': '/api/reference_data/sets',
    'get_mitre_mappings': '/console/plugins/app_proxy:UseCaseManager_Service/api/mappings'
}

OFFENSE_FIELDS = [
    "id",
    "categories",
    "magnitude",
    "domain_id",
    "last_updated_time",
    "event_count",
]

# URLS
GET_SOURCE_ADDRESS_BY_ID = 'api/siem/source_addresses/{0}'  # {0} - Source address ID.
GET_LOCAL_DESTINATION_ADDRESS_BY_ID = 'api/siem/local_destination_addresses/{0}'  # {0} Local destination address ID.
CLOSE_REASON_URL = 'api/siem/offense_closing_reasons'
OFFENSE_URL = 'api/siem/offenses/{0}'
GET_OFFENSE_NOTES_URL = 'api/siem/offenses/{0}/notes'
API_VERSION = "{0}/api/help/versions"
GET_DOMAIN_BY_ID_URL = 'api/config/domain_management/domains/{0}'  # {0} - Domain ID.
GET_DOMAINS = 'api/config/domain_management/domains'
# Queries
# Format Fields -> {offense_id}, {custom_fields}, {time_stamp}, {limit}
EVENT_FIELDS_QUERY = "SELECT \"CRE Name\" AS CREName,\"CRE Description\" AS CREDescription, QIDNAME(qid) AS \"EventName\"," \
                     "QIDDESCRIPTION(qid) AS \"EventDescription\", RuleName(creEventList), partialmatchlist, qid, category," \
                     "AssetHostname(sourceIP, startTime) AS \"sourceHostname\", AssetHostname(destinationIP, startTime) AS" \
                     "\"destinationHostname\", creEventList, credibility, destinationMAC, destinationIP, destinationPort," \
                     " destinationv6, deviceTime, LogSourceTypeName(deviceType) As \"deviceProduct\", domainID, duration, endTime," \
                     "eventCount, eventDirection, processorId, hasIdentity, hasOffense, highLevelCategory, isCREEvent, magnitude, UTF8(payload)," \
                     "postNatDestinationIP, postNatDestinationPort, postNatSourceIP, postNatSourcePort, preNatDestinationIP, preNatDestinationPort," \
                     "preNatSourceIP, preNatSourcePort, ProtocolName(protocolID) AS \"protocolName\", protocolID, relevance," \
                     " severity, sourceIP, sourceMAC, sourcePort, sourcev6, startTime, isunparsed, userName {custom_fields}" \
                     "  FROM events WHERE logsourceid <> 63 AND INOFFENSE({offense_id}) AND startTime" \
                     " > '{unix_timestamp}' LIMIT {limit} LAST {max_days} DAYS"
# START '{time_stamp}' STOP '{end_time}'

GET_EVENTS_DATA_BY_FILTER_QUERY = "Select {field_to_return} from Events where({query_body}) LIMIT {limit} LAST {time_delta} MINUTES"
GET_FLOWS_DATA_BY_FILTER_QUERY = "Select {field_to_return} from Flows where({query_body}) LIMIT {limit} LAST {time_delta} MINUTES"


# CONSTANTS
HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
}

QUERY_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S %p"
SEARCH_COMPLETE_STATUS = 'COMPLETED'
CLOSED_STATUS = 'CLOSED'
EVENTS_FETCH_TIMEOUT_SECONDS = 30
DEFAULT_FIELDS_TO_RETURN = '*'

INVALID_CUSTOM_FIELD_MESSAGE = 'does not exist in catalog'
DESTINATION_ADDRESS_FIELD_DEFAULT = 'destinationip'
SOURCE_ADDRESS_FIELD_DEFAULT = 'sourceip'
HOSTNAME_FIELD_DEFAULT = 'hostname'
USERNAME_FIELD_DEFAULT = 'Username'


class QRadarManager(object):
    """
    Responsible for all QRadar Web Service API functionality
    """

    def __init__(self, api_root, api_token, api_version=None, verify_ssl=False, force_check_connectivity=True):
        self.api_root = api_root  # https://ip_address:port
        self.api = api_token
        # Define session.
        self.session = requests.session()
        HEADERS.update({'SEC': api_token})
        self.session.headers = HEADERS
        if api_version:
            self.session.headers['Version'] = api_version
        self.session.verify = verify_ssl
        self.parser = QRadarParser()
        if force_check_connectivity:
            self.test_connectivity()

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param general_api: {bool} whether to use general api or not
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        api_root = self.api_root

        return urljoin(api_root, API_ENDPOINTS[url_id].format(**kwargs))

    def delete_search_by_id(self, search_id):
        """
        This action gets a search Id and deletes it from QRadar
        :param search_id: {str}
        :return: {str} status
        """
        response = self.session.delete(self._get_full_url('get_search_status_url', search_id=search_id))
        self.validate_response(response)

        return self.parser.get_status_from_search_response(response.json())

    @staticmethod
    def validate_response(response):
        """
        HTTP response validation.
        :param response: {HTTP response object}
        :return: throws exception if there is exception at the response {void}
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as err:
            try:
                json_response = response.json()
                if json_response.get('http_response', {}).get('code', ''):
                    if json_response.get('http_response', {}).get('code', '') == INVALID_AQL_ERROR:
                        if INVALID_CUSTOM_FIELD_MESSAGE in json_response.get('message', ""):
                            raise QRadarCustomFieldValidation()
                        raise QRadarValidationError(json_response.get('message', ""))
                raise QRadarRequestError(
                    'Failed processing request to QRadar, Status Code:{0}, Error:{1}, Content: {2}'.format(
                        response.status_code,
                        str(err),
                        response.content
                    ))
            except QRadarCustomFieldValidation:
                raise
            except QRadarValidationError:
                raise

            except Exception as err:
                raise QRadarRequestError(
                    'Failed processing request to QRadar, Status Code:{0}, Error:{1}, Content: {2}'.format(
                        response.status_code,
                        str(err),
                        response.content
                    ))

    def test_connectivity(self):
        """
        Validates connectivity
        :return: True if the connection is established.
        """
        try:
            response = self.session.get(API_VERSION.format(self.api_root))
            self.validate_response(response)
            return True
        except ConnectionError:
            raise QRadarApiError("{0} server is unreachable".format(self.api_root))

    def lookup_for_value_in_reference_set(self, name, value):
        """
        Check for a value in the given reference set
        :param name: {str} Name of the reference set
        :param value: {str} Value to check in the reference set
        :return: {ReferenceSet} object
        """
        request_url = self._get_full_url('reference_set', set_name=name)
        params = {
            "filter": f"value=\"{value}\""
        }
        response = self.session.get(request_url, params=params)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                return None
            elif response.status_code == 422:
                raise QRadarNotFoundError(e)
            raise Exception(e)
        return self.parser.build_reference_set_object(raw_data=response.json())

    def lookup_for_value_in_reference_map(self, name, value):
        """
        Check for a value in the given reference map
        :param name: {str} Name of the reference map
        :param value: {str} Value to check in the reference map
        :return: {ReferenceMap} object
        """
        request_url = self._get_full_url('reference_map', map_name=name)
        params = {
            "filter": f"value=\"{value}\""
        }
        response = self.session.get(request_url, params=params)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                return None
            elif response.status_code == 422:
                raise QRadarValidationError(e)
            raise Exception(e)
        return self.parser.build_reference_map_object(raw_data=response.json())

    def lookup_for_value_in_reference_table(self, name):
        """
        Check for a value in the given reference table
        :param name: {str} Name of the reference table
        :return: {ReferenceTable} object
        """
        request_url = self._get_full_url('reference_table', table_name=name)
        response = self.session.get(request_url)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                raise QRadarNotFoundError(response.json().get("message"))
            raise Exception(e)
        return self.parser.build_reference_table_object(raw_data=response.json())

    def get_reference_map_by_name(self, name):
        """
        Get a specific reference map by name
        :param name: {str} Name of the reference map
        :return: {ReferenceMap} object
        """
        request_url = self._get_full_url('reference_map', map_name=name)
        response = self.session.get(request_url)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                return None
            elif response.status_code == 422:
                raise QRadarValidationError(e)
            raise Exception(e)
        return self.parser.build_reference_map_object(raw_data=response.json())

    def get_reference_map_of_sets_by_name(self, name):
        """
        Get a specific reference map of sets by name
        :param name: {str} Name of the reference map of sets
        :return: {ReferenceMap} object
        """
        request_url = self._get_full_url('reference_map_of_sets', map_name=name)
        response = self.session.get(request_url)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                raise QRadarNotFoundError(e)
            raise Exception(e)
        return self.parser.build_reference_map_object(raw_data=response.json())

    def get_closing_reason_id(self, reason_name=""):
        """
        Get closing reason id by name
        :param reason_name: {str} Closing reason text
        :return: {int} Id of the reason
        """
        request_url = self._get_full_url('close_reason_url')
        params = {
            "filter": f"text=\"{reason_name}\""
        }
        response = self.session.get(request_url, params=params)
        self.validate_response(response)
        res_data = response.json()
        if res_data:
            return res_data[0].get("id")

    def update_offense(self, offense_id=None, closing_reason_id=None, status=None, assigned_to=None, follow_up=None,
                       protected=None):
        """
        Update offense
        :param offense_id: {int} Id of the offense to update
        :param closing_reason_id: {int} Id for the reason
        :param status: {str} Status to apply
        :param assigned_to: {str} User to assign
        :param follow_up: {bool} Specify if offense should be followed up
        :param protected: {bool} Specify if offense is protected
        :return: {Offense} object
        """
        request_url = self._get_full_url('offense_url', offense_id=offense_id)
        params = {
            "status": status.upper(),
            "assigned_to": assigned_to,
            "follow_up": follow_up,
            "protected": protected
        }
        if closing_reason_id:
            params["closing_reason_id"] = closing_reason_id

        response = self.session.post(request_url, params=params)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                raise QRadarNotFoundError(response.json().get("message"))
            if response.status_code == 422 or response.status_code == 409:
                raise QRadarValidationError(response.json().get("message"))
            raise Exception(e)
        return self.parser.build_siemplify_offense_object(response.json())

    def add_offense_note(self, offense_id, note_text):
        """
        Add note to offense
        :param offense_id: {int} Id of the offense to add note
        :param note_text: {str} Text of the note to add
        :return: {bool} True, exception otherwise
        """
        request_url = self._get_full_url('add_offense_note', offense_id=offense_id)
        params = {
            "note_text": note_text
        }
        response = self.session.post(request_url, params=params)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                raise QRadarNotFoundError(e)
            raise Exception(e)

    def get_reference_maps_of_sets(self, fields_to_return, filter_condition, results_limit):
        """
        Get the reference maps of sets available in Qradar.
        :param fields_to_return: {str} Which fields should be returned by the request
        :param filter_condition: {str} A filter condition to apply to the request
        :param results_limit: {int} Maximum number of elements to return
        :return: {list} List of reference maps
        """
        request_url = self._get_full_url('map_of_sets')
        results_limit = results_limit - 1 if results_limit > 0 else results_limit
        self.session.headers.update({'Range': f"items=0-{results_limit}"})
        params = {}
        if fields_to_return:
            params["fields"] = fields_to_return
        if filter_condition:
            params["filter"] = filter_condition

        response = self.session.get(request_url, params=params)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 422:
                raise QRadarValidationError(response.json().get("message"))
            raise Exception(e)
        return [self.parser.build_reference_map_object(data) for data in response.json()]

    def get_reference_maps(self, fields_to_return, filter_condition, results_limit):
        """
        Get the reference maps available in Qradar.
        :param fields_to_return: {str} Which fields should be returned by the request
        :param filter_condition: {str} A filter condition to apply to the request
        :param results_limit: {int} Maximum number of elements to return
        :return: {list} List of reference maps
        """
        request_url = self._get_full_url('maps')
        results_limit = results_limit - 1 if results_limit > 0 else results_limit
        self.session.headers.update({'Range': f"items=0-{results_limit}"})
        params = {}
        if fields_to_return:
            params["fields"] = fields_to_return
        if filter_condition:
            params["filter"] = filter_condition

        response = self.session.get(request_url, params=params)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 422:
                raise QRadarValidationError(response.json().get("message"))
            raise Exception(e)
        return [self.parser.build_reference_map_object(data) for data in response.json()]

    def get_reference_tables(self, fields_to_return, filter_condition, results_limit):
        """
        Get the reference tables available in Qradar.
        :param fields_to_return: {str} Which fields should be returned by the request
        :param filter_condition: {str} A filter condition to apply to the request
        :param results_limit: {int} Maximum number of elements to return
        :return: {list} List of reference tables
        """
        request_url = self._get_full_url('tables')
        results_limit = results_limit - 1 if results_limit > 0 else results_limit
        self.session.headers.update({'Range': f"items=0-{results_limit}"})
        params = {}
        if fields_to_return:
            params["fields"] = fields_to_return
        if filter_condition:
            params["filter"] = filter_condition

        response = self.session.get(request_url, params=params)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 422:
                raise QRadarValidationError(response.json().get("message"))
            raise Exception(e)
        return [self.parser.build_reference_table_object(data) for data in response.json()]

    def get_reference_map_of_sets(self, name):
        """
        Get the reference map of sets available in Qradar.
        :param name: {str} Name of the reference map
        :return: {ReferenceMap} object
        """
        request_url = self._get_full_url('reference_map_of_sets', map_name=name)
        response = self.session.get(request_url)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                raise QRadarNotFoundError(e)
            raise Exception(e)
        return self.parser.build_reference_map_object(raw_data=response.json())

    def get_reference_sets(self, fields_to_return, filter_condition, results_limit):
        """
        Get the reference sets available in Qradar.
        :param fields_to_return: {str} Which fields should be returned by the request
        :param filter_condition: {str} A filter condition to apply to the request
        :param results_limit: {int} Maximum number of elements to return
        :return: {list} List of reference sets
        """
        request_url = self._get_full_url('sets')
        results_limit = results_limit - 1 if results_limit > 0 else results_limit
        self.session.headers.update({'Range': f"items=0-{results_limit}"})
        params = {}
        if fields_to_return:
            params["fields"] = fields_to_return
        if filter_condition:
            params["filter"] = filter_condition

        response = self.session.get(request_url, params=params)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 422:
                raise QRadarValidationError(response.json().get("message"))
            raise Exception(e)
        return [self.parser.build_reference_set_object(data) for data in response.json()]

    def search_for_items(self, entity, entity_type, action_type, time_delta, limit, fields, source_address_field=None,
                         destination_address_field=None, hostname_field=None, username_field=None):
        """
        Submit for Search Items by entity
        :param entity: {str} entity for search
        :param entity_type: {str} entity type for construct body
        :param action_type: {str} action for events or flows
        :param source_address_field: {str} source address field
        :param destination_address_field: {str} destination address field
        :param hostname_field: {str} hostname field
        :param username_field: {str} username field
        :param time_delta: {int} time by minutes
        :param limit: {int} query limit
        :param fields: {list} fiends to select
        :return search_id for getting data:
        """
        query = copy.deepcopy(GET_EVENTS_DATA_BY_FILTER_QUERY) if action_type == EVENTS_DATA_TYPE_IDENTIFIER \
            else copy.deepcopy(GET_FLOWS_DATA_BY_FILTER_QUERY)
        query_body = self.get_query_body(entity, entity_type, source_address_field, destination_address_field,
                                         hostname_field, username_field)
        query = self.get_query(query, fields, query_body, limit, time_delta)

        self.run_query(query)


        return self.run_query(query)

    def get_query(self, query, fields, query_body, limit, time_delta):
        """
        Format query
        :param query: {str} query string
        :param fields: {list} fiends to select
        :param query_body: {str} logical expression
        :param limit: {int} query limit
        :param time_delta: {int} time by minutes
        :return {str}: Formatted Query
        """
        fields = ', '.join(fields) if fields else DEFAULT_FIELDS_TO_RETURN
        return query.format(field_to_return=fields, query_body=query_body, limit=limit, time_delta=time_delta)

    def get_query_body(self, entity, entity_type, source_address_field=None, destination_address_field=None,
                       hostname_field=None, username_field=None):
        """
        Format query body
        :param entity: {str} entity for search
        :param entity_type: {str} entity type for construct body
        :param source_address_field: {str} source address field
        :param destination_address_field: {str} destination address field
        :param hostname_field: {str} hostname field
        :param username_field: {str} username field
        :return {str} query logical part:
        """
        if entity_type == EntityTypes.ADDRESS:
            return "{} = '{}' or {} = '{}'"\
                .format(source_address_field or SOURCE_ADDRESS_FIELD_DEFAULT, entity, destination_address_field or
                        DESTINATION_ADDRESS_FIELD_DEFAULT, entity)
        if entity_type == EntityTypes.HOSTNAME:
            return "{} = '{}'".format(hostname_field or HOSTNAME_FIELD_DEFAULT, entity)
        if entity_type == EntityTypes.USER:
            return "{} = '{}'".format(username_field or USERNAME_FIELD_DEFAULT, entity)

    def get_offenses_by_filter(self, *, filter, sort=None, fields=OFFENSE_FIELDS):
        """
         Retrieve offenses by filter
         :param fields: {list} List of fields to retrieve
         :param filter: {str} filter e.x 'status=OPEN AND ... OR'
         :param sort: {str}
         :return: list of dicts when each dict represent an offense {list}
        """
        params = {
            'fields': ','.join(fields),
            'filter': filter,
        }
        if sort:
            params['sort'] = sort

        params = {k: v for k, v in params.items() if v is not None}

        response = self.session.get(self._get_full_url('offenses'), params=params)
        self.validate_response(response)

        return self.parser.build_results(response.json(), 'build_siemplify_offense_object')

    def get_updated_offenses_from_time(self, timestamp_unix_time, status=OFFENSES_STATUS_OPEN, fields=None):
        """
        Retrieve updated offenses since unix time.
        :param timestamp_unix_time: {int | str} get updated offenses since time stamp
        :param status: {str} the status of the offenses to fetch
        :param fields: the status of the offenses to fetch {str}
        :return: list of dicts when each dict represent an offense {list}
        """
        fields = fields or OFFENSE_FIELDS
        filter = "last_updated_time>={} AND status = \"{}\"".format(timestamp_unix_time, status)
        offences = self.get_offenses_by_filter(filter=filter, fields=fields)
        # Sort offences by last update time.
        offences.sort(key=lambda offense: offense.last_updated_time or 1)

        return offences

    def get_all_closing_reasons(self):
        """
        Retrieve a list of all offense closing reasons.
        :return: {list} List of all offense closing reasons Reason instances
        """
        response = self.session.get(self._get_full_url('close_reason_url'))
        self.validate_response(response)

        return self.parser.build_reasons_objects_list(response.json())

    def create_close_reason(self):
        """
        Create an offense closing reason.
        :return: {Reason} closing Reason model instance
        """
        response = self.session.post(self._get_full_url('close_reason_url'), params={'reason': SIEMPLIFY_CLOSE_REASON})
        self.validate_response(response)

        return self.parser.build_reason_object(response.json())

    def get_offense(self, offense_id):
        """
        Create an offense closing reason.
        :param offense_id: {string} The ID of the offense to update.
        :return: {Offense} closing Offense model instance
        """
        response = self.session.get(self._get_full_url('offense_url', offense_id=offense_id))
        self.validate_response(response)

        return self.parser.build_siemplify_offense_object(response.json())

    def close_offense(self, offense_id, closing_reason_id):
        """
        Close offense by changing his status to 'CLOSED'
        When the status of an offense is being set to CLOSED, a valid closing_reason_id must be provided.
        :param offense_id: {string} The ID of the offense to update.
        :param closing_reason_id: {string} The ID of a closing reason. You must provide a valid closing_reason_id when you close an offense.
        :return:
        """
        # Validate offense not already closed
        offense_data = self.get_offense(offense_id)
        if offense_data.status == CLOSED_STATUS:
            return offense_data
        # Close offense
        data = {'closing_reason_id': closing_reason_id, 'status': CLOSED_STATUS}
        request_url = self._get_full_url('offense_url', offense_id=offense_id)
        response = self.session.post(request_url, params=data)
        self.validate_response(response)

        return self.parser.build_siemplify_offense_object(response.json())

    def run_query(self, query):
        """
        Run QRadar query.
        :param query: AQL query to be sent to QRadar {string}
        :return: Search ID from submitted query {string}
        """
        query = urllib.parse.quote_plus(query)
        response = self.session.post(self._get_full_url('run_query', query=query))
        self.validate_response(response)

        return self.parser.get_search_id_from_search_response(response.json())

    def is_search_completed(self, query_result_id):
        """
        :param query_result_id: Search ID in QRadar {string}
        :return: True if the query completed else False {bool}
        """
        response = self.session.get(self._get_full_url('get_search_status_url', search_id=query_result_id))
        self.validate_response(response)

        return self.parser.get_status_from_search_response(response.json()) == SEARCH_COMPLETE_STATUS

    def get_completed_search_query_result(self, query_result_id, build_with=None):
        """
        Retrieves search results from QRadar.
        :param query_result_id: {str} Search ID in QRadar.
        :param build_with: {str} Specify the parser method name to build the result.
        :return: {dict | model instance} Query Data from QRadar: type can be dict or model instance depends on build_with argument
        """
        response = self.session.get(self._get_full_url('get_search_results_url', search_id=query_result_id))
        self.validate_response(response)
        # Delete search from QRadar
        self.delete_search_by_id(query_result_id)

        if build_with:
            return getattr(self.parser, build_with)(response.json())

        return response.json()

    def get_search_results(self, query_result_id, time_out_in_seconds=None, build_with=None):
        """
        Retrieves search results from QRadar.
        :param query_result_id: {str} Search ID in QRadar.
        :param time_out_in_seconds: {str} time out in seconds.
        :param build_with: {str} Specify parser method name to build the result.
        :return: {dict} Query Data from QRadar
        """
        # Fetch results.
        while not self.is_search_completed(query_result_id):
            time.sleep(5)
            if time_out_in_seconds:
                timeout_time = datetime.datetime.now() + datetime.timedelta(seconds=time_out_in_seconds)
                if datetime.datetime.now() >= timeout_time:
                    raise QRadarApiError('Timeout fetching events for query id: {0}'.format(query_result_id))

        return self.get_completed_search_query_result(query_result_id, build_with)

    def get_search_report(self, search_id, report_type=None):
        """
        Retrieves search results from QRadar.
        :param search_id: {str} Search ID in QRadar.
        :param report_type: {str} for guess which parser method call.
        :return: {list} List of Event or FLow instance
        """
        response = self.session.get(self._get_full_url('get_search_results_url', search_id=search_id))
        self.validate_response(response)
        self.delete_search_by_id(search_id)

        return self.parser.build_siemplify_flaw_object_list(response.json()) \
            if report_type == FLOWS_DATA_TYPE_IDENTIFIER \
            else self.parser.build_siemplify_event_object_list(response.json())

    def get_events_by_offense_id(self, offense_id, custom_fields, unix_timestamp, datetime_timestamp,
                                 datetime_end_timestamp, events_limit_per_offense=1000, max_days_backwards=1,
                                 page_size=None):
        """
        Get events for offense for time.
        :param offense_id: offense id {string}
        :param custom_fields: events custom fields {string}
        :param unix_timestamp: time to fetch events from {unix time}
        :param datetime_timestamp: time to fetch events from {datetime} (AQL START query)
        :param datetime_end_timestamp: time to fetch events till {datetime} (AQL STOP query)
        :param events_limit_per_offense: {int}
        :param max_days_backwards: {int} max days backwards for Qradar query (LAST X DAYS)
        :param page_size: {int} page size
        :return: Result dict when each key will be a rule and the events that contain its rule {dict} -
                Example: {"rule1":[{event1}, {event2}]}
        """

        # Query start and end time.
        query_start_time = datetime_timestamp.strftime(QUERY_TIMESTAMP_FORMAT)
        query_end_time = datetime_end_timestamp.strftime(QUERY_TIMESTAMP_FORMAT)

        # If there is custom fields add comma at the query before the fields.
        if custom_fields:
            # Warp all custom fields with quotes.
            custom_fields = string_to_multi_value(custom_fields)
            custom_fields = ', {0}'.format(",".join(['"{0}"'.format(field) for field in custom_fields]))
        else:
            custom_fields = ""

        # Form Query.
        # OLD - with start and end time!
        query = EVENT_FIELDS_QUERY.format(offense_id=offense_id,
                                          custom_fields=custom_fields,
                                          unix_timestamp=unix_timestamp,
                                          time_stamp=query_start_time,
                                          end_time=query_end_time,
                                          limit=events_limit_per_offense,
                                          max_days=max_days_backwards)

        query_result_id = self.run_query(query)
        # Fetch query result.
        events = self.get_search_results(query_result_id, build_with='build_siemplify_event_object_list')

        # Get correlation in case there are no new events
        if not events:
            query_str = EVENT_FIELDS_QUERY.replace("logsourceid <> 63", "logsourceid = 63")
            query = query_str.format(offense_id=offense_id,
                                     custom_fields=custom_fields,
                                     unix_timestamp=unix_timestamp,
                                     time_stamp=query_start_time,
                                     end_time=query_end_time,
                                     limit=events_limit_per_offense,
                                     max_days=max_days_backwards)
            query_result_id = self.run_query(query)
            events = self.get_search_results(query_result_id, build_with='build_siemplify_event_object_list')

        return events

    def get_domain_name_by_id(self, domain_id):
        """
        Get tenant name by id.
        :param domain_id: tenant id {string/int}
        :return: tenant name {string}
        """
        request_url = urllib.parse.urljoin(self.api_root, GET_DOMAIN_BY_ID_URL.format(domain_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json().get('name')

    def get_domains(self):
        """
        Get domains
        :return: {[Domain]} List of Domain data models
        """
        request_url = urllib.parse.urljoin(self.api_root, GET_DOMAINS)
        response = self.session.get(request_url)
        self.validate_response(response)
        return self.parser.build_domain_obj_list(response.json())

    def get_offense_notes(self, offence_id):
        """
        Get offence notes by id.
        :param offence_id: id of an offence {string/integer}
        :return: {list}
        """
        request_url = urllib.parse.urljoin(self.api_root, GET_OFFENSE_NOTES_URL.format(offence_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json()

    def get_source_address_obj_by_id(self, source_address_id):
        """
        Get source address object by id.
        :param source_address_id: object id {string}
        :return: source address object {dict}
        """
        request_url = urllib.parse.urljoin(self.api_root, GET_SOURCE_ADDRESS_BY_ID.format(source_address_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json()

    def get_local_destination_address_obj_by_id(self, local_destination_address_id):
        """
        Get local destination address object by id.
        :param local_destination_address_id: object id {string}
        :return: local destination address object {dict}
        """
        request_url = urllib.parse.urljoin(self.api_root, GET_LOCAL_DESTINATION_ADDRESS_BY_ID.format(
            local_destination_address_id))
        response = self.session.get(request_url)
        self.validate_response(response)
        return response.json()

    def get_offense_summary(self, offence_id):
        """
        Get offence summary by offence id.
        :param offence_id: offense's id number {string/integer}
        :return: offense summery data {dict}
        """
        offence_summary = {}
        # fetch offence data.
        offence_summary['offence'] = self.get_offense(offence_id)
        # Fetch source addresses object.
        offence_summary['source_addresses'] = []
        for source_address_id in offence_summary['offence'].get('source_address_ids'):
            offence_summary['source_addresses'].append(self.get_source_address_obj_by_id(source_address_id))
        # Fetch local destination addresses objects.
        for local_dest_address_id in offence_summary['offence'].get('local_destination_address_ids'):
            offence_summary['local_destination_addresses'].append(self.get_local_destination_address_obj_by_id(
                local_dest_address_id))
        # Fetch offence notes.
        offence_summary['notes'] = self.get_offense_notes(offence_id)

        return offence_summary

    def get_mitre_mappings(self):
        """
        Get MITRE details about rules in Qradar.
        :return: {list} List of MITRE mapping objects
        """
        request_url = self._get_full_url('get_mitre_mappings')
        self.session.cookies.clear()
        response = self.session.get(request_url)
        try:
            self.validate_response(response)
        except Exception as e:
            if response.status_code == 404:
                raise QRadarNotFoundError("Use Case Manager is not installed")
            raise Exception(e)
        return self.parser.build_list_of_mappings(response.json())

    @staticmethod
    def build_aql_query(select_fields, table_name, where_condition=None, sort_by_field=None, sort_order=None, limit=None,
                        time_delta=None, start_time=None, stop_time=None):
        """
        Build AQL search query
        :param select_fields: {str} Selected fields to query
        :param table_name: {str} Query table name. Can be events or flows.
        :param where_condition: {str} Where condition. For example (severity > 3 AND category = 5018)
        :param sort_by_field: {str} Field to order by the results.
        :param sort_order: {str} Sort order, applicable only if sort_by_field parameter is provided. Can be ASC or DESC.
        :param limit: {int} Max results to return
        :param time_delta: {int} Return results time frame. Example: Last 7 Days.
        :param start_time: {str} Start time period. Will be applied only if time_delta was not provided. Example format: 2017-01-01 09:00:00
        :param stop_time: {str} End time period. Example format: 2017-01-01 09:00:00
        :return: {str} AQL query
        """
        query = f"SELECT {select_fields} FROM {table_name} "
        if where_condition:
            query += f" WHERE {where_condition} "
        if sort_by_field:
            query += f"ORDER BY {sort_by_field} "
            if sort_order:
                query += f"{sort_order} "
        if isinstance(limit, int):
            query += f"LIMIT {limit} "

        if time_delta:
            query += f"{time_delta}"
        else:
            if start_time:
                query += f"START '{start_time}' "
            if stop_time:
                query += f"STOP '{stop_time}' "

        return query
