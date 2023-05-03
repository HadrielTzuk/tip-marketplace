# ============================================================================#
# title           :XDRManager.py
# description     :This Module contain all Cortex XDR operations functionality
# author          :zivh@siemplify.co
# date            :08-04-2019
# python_version  :2.7
# libreries       :
# requirments     :
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #
import pytz
import requests
import arrow
import secrets
import string
import hashlib
from enum import Enum
from PaloAltoCortexXDRTransformationLayer import PaloAltoCortexXDRTransformationLayer


# ============================= CONSTS ===================================== #
ALERTS_DEFAULT_LIMIT = 1000
ALREADY_EXISTS_ERR_CODE = 500
ALREADY_EXISTS_ERR_MSG = "All hashes have already been added to the allow or block list"

# ============================= CLASSES ===================================== #

class XDRNotFoundException(Exception):
    pass


class XDRException(Exception):
    pass


class XDRAlreadyExistsException(Exception):
    pass


class CortexSortTypesEnum(Enum):
    # sort order by modification_time or by modification_time
    SORT_BY_CREATION_TIME = "creation_time"
    SORT_BY_MODIFICATION_TIME = "modification_time"


class CortexSortOrderEnum(Enum):
    # sort order by ascending order or descending order
    SORT_BY_ASC_ORDER = "asc"
    SORT_BY_DESC_ORDER = "desc"


class CortexCreationFilterEnum(Enum):
    # Filter by creation time
    GTE_CREATION_TIME = "gte"
    LTE_CREATION_TIME = "lte"


class CortexModificationFilterEnum(Enum):
    # Filter by modification time
    GTE_MODIFICATION_TIME = "gte"
    LTE_MODIFICATION_TIME = "lte"


class LOGGER(object):
    def __init__(self, logger):
        self.logger = logger

    def info(self, msg):
        if self.logger:
            self.logger.info(msg)


class XDRManager(object):

    def __init__(self, server_address, api_key, api_key_id, verify_ssl=True, logger=None):
        self.api_root = server_address[:-1] if server_address.endswith(u"/") else server_address
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.LOGGER = LOGGER(logger)
        self.session = requests.Session()
        self.session.verify = verify_ssl
        headers = self.calculate_headers()
        if self.connect_to_xdr(headers):
            self.session.headers.update(headers)

        self.transformation_layer = PaloAltoCortexXDRTransformationLayer()

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:

            try:
                response.json()
            except Exception:
                raise XDRException(
                    "{error_msg}: {error} - {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=response.content)
                )

            if response.json().get("reply", {}).get(u"err_code") == ALREADY_EXISTS_ERR_CODE and \
                    response.json().get("reply", {}).get(u"err_extra") == ALREADY_EXISTS_ERR_MSG:
                raise XDRAlreadyExistsException(
                    "{error} - {text}".format(
                        error=response.json().get("reply", {}).get(u"err_msg"),
                        text=response.json().get("reply", {}).get(u"err_extra", response.content)
                    )
                )

            raise XDRException(
                "{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=response.json().get("reply", {}).get(u"err_msg"),
                    text=response.json().get("reply", {}).get(u"err_extra", response.content)
                )
            )

    def calculate_headers(self):
        """
        There are two types of API keys that you can generate from your Cortex XDR: Investigation and Response
        app based on your desired security level: standard and advanced.
        authorization calculation explanation:
        https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis.html
        NOTE: We have test the advanced key
        :return: {dict} headers
        """
        self.LOGGER.info("Calculate headers for authentication")
        # Generate a 64 bytes random string
        nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
        # Get the current timestamp as milliseconds.
        timestamp = int(arrow.now(pytz.utc).timestamp) * 1000
        # Generate the auth key:
        auth_key = "%s%s%s" % (self.api_key, nonce, timestamp)
        # Convert to bytes object
        auth_key = auth_key.encode("utf-8")
        # Calculate sha256:
        api_key_hash = hashlib.sha256(auth_key).hexdigest()
        # Generate HTTP call headers
        headers = {
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(self.api_key_id),
            "Authorization": api_key_hash
        }
        return headers

    def connect_to_xdr(self, headers):
        """
        test advanced authentication
        :param headers: {dict} headers after calculation
        :return: {boolean} true if authenticated
        """
        res = self.session.post(
            url="{0}/api_keys/validate/".format(self.api_root),
            headers=headers,
            json={})

        self.validate_response(res)
        self.LOGGER.info("Successfully authenticated")
        return res.json()

    def get_incidents(self, incident_id_list=None, modification_time=None, modification_filter_enum=None,
                      creation_time=None, creation_filter_enum=None,
                      search_from=0, search_to=100, sort_type=None, sort_order=None):
        """
        Gets a list of incidents filtered by a list of incident IDs, modification time, or creation time. Filtering by
        multiple fields will be concatenated using AND condition (OR is not supported).

        field can be modification_time, creation_time, or incident_id_list.
        operator: Can be gte (greater than or equal to), lte (less than or equal to), or in
        value: modification or creation time (integer), timestamp in epoch milliseconds, UTC time zone OR incident_ids

        :param incident_id_list: {list} a list containing incident IDs - Filter by incident ids
        :param search_from: {int} Offset within the query result set from which you want incidents returned
        Incidents are returned as a zero-based list. Any incident indexed less than this value is not returned.
        :param search_to: {int} Offset within the result set after which you do not want incidents returned.
        Any incident that indexed higher than this value are not returned. 100 is the limit
        Defaults to zero, which returns all incidents to the end of the list.
        :param modification_time: {unix time} timestamp in epoch milliseconds, UTC time zone
        :param modification_filter_enum: {Enum} modification filter can have one from two operators (gte or lte) (not both)
        :param creation_time: {unix time} timestamp in epoch milliseconds, UTC time zone
        :param creation_filter_enum: {Enum} creation filter can have one from two operators (gte or lte) (not both)
        :param sort_type: {Enum} incidents can be sorted by modification time or creation time (not both)
        :param sort_order:{Enum} incidents can be order in ascending order or descending

        :return: {list} of dicts. each of which represents a single incident.
        """
        request_data = {'filters': [],
                        'search_from': search_from,
                        'search_to': search_to,
                        'sort': {}}

        filters = request_data["filters"]
        request_data['search_from'] = search_from
        request_data['search_to'] = search_to

        # using Enum for sort fields because only one should be provided. not both!
        if sort_type:
            request_data['sort'].update({'field': sort_type.value})
        if sort_order:
            request_data['sort'].update({'keyword': sort_order.value})

        if incident_id_list and isinstance(incident_id_list, list):
            filters.append({'field': 'incident_id_list', 'operator': 'in', 'value': incident_id_list})

        if creation_filter_enum and creation_time:
            filters.append(
                {'field': 'creation_time', 'operator': creation_filter_enum.value, 'value': creation_time})
        if modification_filter_enum and modification_time:
            filters.append(
                {'field': 'modification_time', 'operator': modification_filter_enum.value, 'value': modification_time})

        res = self.session.post("{0}/public_api/v1/incidents/get_incidents/".format(self.api_root),
                                json={'request_data': request_data})
        self.validate_response(res)
        # returns an array of JSON objects, each of which represents a single incident.
        return res.json().get('reply', {}).get('incidents', [])

    def get_extra_incident_data(self, incident_id, alerts_limit=ALERTS_DEFAULT_LIMIT):
        """
        Get extra data fields of a specific incident including alerts and key artifacts.
        :param incident_id: {string} The ID of the incident for which you want to retrieve extra data.
        :param alerts_limit: {int} Maximum number of related alerts in the incident to retrieve (default is 1000)
        :return: {dict} the additional incident information including: alerts, network artifacts, and file artifacts.
        """
        request_data = {"incident_id": incident_id,
                        "alerts_limit": alerts_limit}
        res = self.session.post("{0}/public_api/v1/incidents/get_incident_extra_data/".format(self.api_root),
                                json={'request_data': request_data})
        self.validate_response(res)
        # returns JSON object containing the additional incident information including
        # the alerts, network artifacts, and file artifacts.
        return res.json().get('reply', {})

    def update_an_incident(self, incident_id, assigned_user=None, severity=None, status=None, resolve_comment=None):
        """
        Update one or more fields of a specific incident. Missing fields are ignored.
        :param incident_id: {string} An integer representing the incident ID to be updated.
        :param assigned_user: {string} The updated full name of the incident assignee.
        :param severity: {string} Administrator-defined severity, one of the following (case insensitive):
        High, Medium, Low. To remove a manually set severity pass "none" or ""
        :param status: {string} Updated incident status, one of the following: NEW, UNDER_INVESTIGATION,
        RESOLVED_THREAT_HANDLED, RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE, RESOLVED_OTHER
        :param resolve_comment: {string} Descriptive comment explaining the incident change.
        """
        request_data = {"incident_id": incident_id,
                        "update_data": {}}

        if assigned_user:
            request_data["update_data"]["assigned_user_pretty_name"] = assigned_user
        if severity:
            request_data["update_data"]["manual_severity"] = severity
        if status:
            request_data["update_data"]["status"] = status

        if resolve_comment:
            request_data["update_data"]["resolve_comment"] = resolve_comment

        res = self.session.post("{0}/public_api/v1/incidents/update_incident/".format(self.api_root),
                                json={'request_data': request_data})
        self.validate_response(res)
        if not res.json()['reply']:
            raise XDRException('Failed to update incident data: {0}.'.format(incident_id))

    def get_all_endpoints(self, limit=100):
        """raw_endpoints = []
        offset = 0
        while limit > 0:
            res = self.session.post(u"{0}/public_api/v1/endpoints/get_endpoints/".format(self.api_root), json={"limit": limit, "offset": offset})
            self.validate_response(res)
            r = res.json().get(u"reply", [])
            raw_endpoints.extend(r)
            raise Exception(len(r))
            limit -= len(r)
            offset += len(r)
        endpoints = []
        for endpoint in raw_endpoints[:limit]:
            endpoints.append(self.get_endpoint_by_id(endpoint.get(u"agent_id")))

        return endpoints"""
        if not limit:
            limit = 100
        res = self.session.post(u"{0}/public_api/v1/endpoints/get_endpoints/".format(self.api_root))
        self.validate_response(res)
        raw_endpoints = res.json().get(u"reply", [])
        endpoints = []
        for endpoint in raw_endpoints[:limit]:
            endpoints.append(self.get_endpoint_by_id(endpoint.get(u"agent_id")))

        return endpoints

    def get_endpoint_by_id(self, endpoint_id):
        request_data = {
            "filters": [
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": [
                        endpoint_id
                    ]
                }
            ]}

        res = self.session.post(u"{0}/public_api/v1/endpoints/get_endpoint/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply') or not res.json().get(u"reply", {}).get(u"endpoints", []):
            raise XDRNotFoundException(u'Unable to get endpoint {0}.'.format(endpoint_id))

        return self.transformation_layer.build_siemplify_endpoint_obj(res.json()[u"reply"][u"endpoints"][0])

    def get_endpoint_by_ip(self, ip_address):
        request_data = {
            "filters": [
                {
                    "field": "ip_list",
                    "operator": "in",
                    "value": [
                        ip_address
                    ]
                }
            ]}

        res = self.session.post(u"{0}/public_api/v1/endpoints/get_endpoint/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply') or not res.json().get(u"reply", {}).get(u"endpoints", []):
            raise XDRNotFoundException(u'Unable to get endpoint for IP {0}.'.format(ip_address))

        return self.transformation_layer.build_siemplify_endpoint_obj(res.json()[u"reply"][u"endpoints"][0])

    def get_endpoint_by_hostname(self, hostname):
        request_data = {
            "filters": [
                {
                    "field": "hostname",
                    "operator": "in",
                    "value": [
                        hostname
                    ]
                }
            ]}

        res = self.session.post(u"{0}/public_api/v1/endpoints/get_endpoint/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply') or not res.json().get(u"reply", {}).get(u"endpoints", []):
            raise XDRNotFoundException(u'Unable to get endpoint for hostname {0}.'.format(hostname))

        return self.transformation_layer.build_siemplify_endpoint_obj(res.json()[u"reply"][u"endpoints"][0])

    def get_endpoints(self, ip_addresses=None, hostnames=None, platforms=None, aliases=None, isolation_status=None,
                      group_names=None, endpoint_ids=None, limit=100):
        filters = []

        if ip_addresses:
            filters.append(
                {
                    "field": "ip_list",
                    "operator": "in",
                    "value": ip_addresses
                }
            )

        if hostnames:
            filters.append(
                {
                    "field": "hostname",
                    "operator": "in",
                    "value": hostnames
                }
            )

        if platforms:
            filters.append(
                {
                    "field": "platform",
                    "operator": "in",
                    "value": platforms
                }
            )

        if group_names:
            filters.append(
                {
                    "field": "group_name",
                    "operator": "in",
                    "value": group_names
                }
            )

        if aliases:
            filters.append(
                {
                    "field": "alias",
                    "operator": "in",
                    "value": aliases
                }
            )

        if isolation_status:
            filters.append(
                {
                    "field": "isolate",
                    "operator": "in",
                    "value": [isolation_status]
                }
            )

        if endpoint_ids:
            filters.append(
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": endpoint_ids
                }
            )

        request_data = {
            "filters": filters,
            "limit": limit
        }

        res = self.session.post(u"{0}/public_api/v1/endpoints/get_endpoint/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply'):
            raise XDRException(u'Unable to list endpoints')

        return [self.transformation_layer.build_siemplify_endpoint_obj(endpoint_data) for endpoint_data in
                res.json()[u"reply"][u"endpoints"]]

    def isolate_endpoint(self, endpoint_id):
        res = self.session.post(u"{0}/public_api/v1/endpoints/isolate/".format(self.api_root),
                                json={u'request_data': {u'endpoint_id': endpoint_id}})
        self.validate_response(res)
        return True

    def unisolate_endpoint(self, endpoint_id):
        res = self.session.post(u"{0}/public_api/v1/endpoints/unisolate/".format(self.api_root),
                                json={u'request_data': {u'endpoint_id': endpoint_id}})
        self.validate_response(res)
        return True

    def scan_endpoint(self, endpoint_id):
        request_data = {
            "filters": [
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": [
                        endpoint_id
                    ]
                }
            ]}

        res = self.session.post(u"{0}/public_api/v1/audits/endpoints/scan/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)
        return True

    def cancel_scan_endpoint(self, endpoint_id):
        request_data = {
            "filters": [
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": [
                        endpoint_id
                    ]
                }
            ]}

        res = self.session.post(u"{0}/public_api/v1/audits/endpoints/abort_scan/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)
        return True

    def delete_endpoint(self, endpoint_id):
        request_data = {
            "filters": [
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": [
                        endpoint_id
                    ]
                }
            ]}

        res = self.session.post(u"{0}/public_api/v1/audits/endpoints/delete/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)
        return True

    def get_device_violations(self, hostnames=None, products=None, usernames=None, vendors=None, types=None,
                              endpoint_ids=None, start_timestamp=None, end_timestamp=None, ip_addresses=None,
                              violation_ids=None,
                              limit=100):
        """

        :param hostnames: {[]} Filter by hostnames
        :param products:  {[]} Filter by products
        :param usernames: {[]} Filter by usernames
        :param vendors:  {[]} Filter by vendors
        :param types:  {[]} Filter by types. Valid values: cd-rom, disk, floppy disk, portabledevice
        :param endpoint_ids:  {[]} Filter by endpoints
        :param start_timestamp: {long} Filter by start timestamp of the violation (unix time)
        :param end_timestamp: {long} Filter by start timestamp of the violation (unix time)
        :param ip_addresses:  {[]} {Filter by IP addresses
        :param violation_ids:  {[]} Filter by violations IDs
        :return: {[]} List of found violations
        """
        if not limit:
            limit = 100
        filters = []

        if start_timestamp:
            filters.append(
                {
                    "field": "timestamp",
                    "operator": "gte",
                    "value": start_timestamp
                }
            )

        if end_timestamp:
            filters.append(
                {
                    "field": "timestamp",
                    "operator": "lte",
                    "value": end_timestamp
                }
            )

        if ip_addresses:
            filters.append(
                {
                    "field": "ip_list",
                    "operator": "in",
                    "value": ip_addresses
                }
            )

        if hostnames:
            filters.append(
                {
                    "field": "hostname",
                    "operator": "in",
                    "value": hostnames
                }
            )

        if products:
            filters.append(
                {
                    "field": "product",
                    "operator": "in",
                    "value": products
                }
            )

        if usernames:
            filters.append(
                {
                    "field": "username",
                    "operator": "in",
                    "value": usernames
                }
            )

        if vendors:
            filters.append(
                {
                    "field": "vendor",
                    "operator": "in",
                    "value": vendors
                }
            )

        if endpoint_ids:
            filters.append(
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": endpoint_ids
                }
            )

        if violation_ids:
            filters.append(
                {
                    "field": "violation_id_list",
                    "operator": "in",
                    "value": violation_ids
                }
            )

        if types:
            filters.append(
                {
                    "field": "type",
                    "operator": "in",
                    "value": types
                }
            )

        request_data = {
            "filters": filters
        }

        res = self.session.post(u"{0}/public_api/v1/audits/device_control/get_violations".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply'):
            raise XDRException(u'Unable to list device violations')

        return [self.transformation_layer.build_siemplify_device_violation_obj(violation_data) for violation_data in
                res.json()[u"reply"][u"violations"]]

    def get_endpoint_agent_report(self, endpoint_id):
        request_data = {
            "filters": [
                {
                    "field": "endpoint_id",
                    "operator": "in",
                    "value": [
                        endpoint_id
                    ]
                }
            ]}

        res = self.session.post(u"{0}/public_api/v1/audits/agents_reports/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply') or not res.json()[u"reply"].get(u"data"):
            raise XDRException(u'Unable to get agent report for endpoint {}'.format(endpoint_id))

        return self.transformation_layer.build_siemplify_agent_report_obj(res.json()[u"reply"][u"data"][0])

    def quarantine_file_on_endpoint(self, endpoint_id, file_path, file_hash):
        """
        Quarantine file on an endpoint by its ID
        :param endpoint_id: {str} The endpoint ID
        :param file_path: {str} The path of the file you want to quarantine.
        :param file_hash: {str} The file's hash. Hash must be a valid SHA256.
        :return:
        """
        request_data = {
            "filters": [
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": [
                        endpoint_id
                    ]
                }
            ],
            "file_path": file_path,
            "file_hash": file_hash
        }

        res = self.session.post(u"{0}/public_api/v1/audits/endpoints/quarantine/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply'):
            raise XDRException(u'Unable to quarantine file on endpoint {}'.format(endpoint_id))

        return True

    def restore_file_on_endpoint(self, endpoint_id, file_hash):
        """
        Restore file on an endpoint by its ID
        :param endpoint_id: {str} The endpoint ID
        :param file_hash: {str} The file's hash. Hash must be a valid SHA256.
        :return:
        """
        request_data = {
            "endpoint_id": endpoint_id,
            "file_hash": file_hash
        }

        res = self.session.post(u"{0}/public_api/v1/audits/endpoints/restore/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply'):
            raise XDRException(u'Unable to quarantine file on endpoint {}'.format(endpoint_id))

        return True

    def whitelist_file_on_endpoint(self, file_hash, comment=None):
        """
        Whitelist file on an endpoint by its ID
        :param file_hash: {str} The file's hash. Hash must be a valid SHA256.
        :param comment: {str} String that represents additional information regarding the action.
        :return:
        """
        request_data = {
            "hash_list": [file_hash]
        }

        if comment:
            request_data["comment"] = comment

        res = self.session.post(u"{0}/public_api/v1/audits/hash_exceptions/whitelist/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply'):
            raise XDRException(u'Unable to whitelist hash {}'.format(file_hash))

        return True

    def blacklist_file_on_endpoint(self, file_hash, comment=None):
        """
        Blacklist file on an endpoint by its ID
        :param file_hash: {str} The file's hash. Hash must be a valid SHA256.
        :param comment: {str} String that represents additional information regarding the action.
        :return:
        """
        request_data = {
            "hash_list": [file_hash]
        }

        if comment:
            request_data["comment"] = comment

        res = self.session.post(u"{0}/public_api/v1/audits/hash_exceptions/blacklist/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply'):
            raise XDRException(u'Unable to blacklist hash {}'.format(file_hash))

        return True

    def retrieve_file_from_endpoint(self, endpoint_id, os_type, file_path):
        request_data = {
            "filters": [
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": [
                        endpoint_id
                    ]
                }
            ],
            "files": {
                os_type:
                    [
                        file_path
                    ]
            }
        }

        res = self.session.post(u"{0}/public_api/v1/audits/endpoints/file_retrieval/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply'):
            raise XDRException(u'Unable to retrieve file {} from endpoint {}'.format(file_path, endpoint_id))

        return res.json().get(u"reply")

    def add_hash_to_block_list(self, file_hash, comment=None):
        """
        Add file to a block list
        :param file_hash: {str} The file's hash. Hash must be a valid SHA256.
        :param comment: {str} String that represents additional information regarding the action.
        :return: {bool} True if successful, exception otherwise.
        """
        request_data = {
            "hash_list": [file_hash]
        }

        if comment:
            request_data["comment"] = comment

        res = self.session.post(u"{0}/public_api/v1/hash_exceptions/blocklist/".format(self.api_root),
                                json={u'request_data': request_data})
        self.validate_response(res)

        if not res.json().get(u'reply'):
            raise XDRException(u'Unable to add hash {} to a block list.'.format(file_hash))

        return True

    @staticmethod
    def is_sha256(file_hash):
        return len(file_hash) == 64
