# ============================================================================#
# title           :SophosManager.py
# description     :This Module contain all Sophos operations functionality
# author          :avital@siemplify.co
# date            :24-12-2019
# python_version  :2.7
# libreries       :requests, base64
# requirements    :
# product_version :
# ============================================================================#

# ============================= IMPORTS ===================================== #

import requests
import base64
import urlparse
import json
from SophosParser import SophosParser
from constants import LIMIT_PER_REQUEST, UNISOLATED_JSON_RESPONSE, ISOLATION_IN_PROGRESS, ISOLATED, UNISOLATED
from utils import validate_api_response
from SophosExceptions import SophosManagerError, HashAlreadyOnBlocklist
# Consult with Roi - Python 2
from SiemplifyDataModel import EntityTypes
from TIPCommon import SiemplifySession  # TIP The Package
from TIPCommon import filter_old_alerts  # TIP The Module
# ============================== CONSTS ===================================== #

API_ROOT = u"https://id.sophos.com"
MULTI_AUTH_INDICATOR_KEY = "mfa_required"
LIMIT = 10000
EVENTS_LIMIT = 1000
KNOWN_SERVICES_STATUSES = {
    "2": "Missing",
    "0": "OK"
}

# ============================= CLASSES ===================================== #


ENDPOINTS = {
    u"get_alerts": u"/gateway/siem/v1/alerts",
    u"get_api_root": u"/whoami/v1",
    u"test_connectivity": u"/endpoint/v1/endpoints",
    u"test_siem_connectivity": u"/gateway/siem/v1/events",
    u"initiate_scan": u"/endpoint/v1/endpoints/{scan_id}",
    u"find_entities": u"/endpoint/v1/endpoints",
    u"check_isolation_status": u"/endpoint/v1/endpoints/{endpoint_id}/isolation",
    u"isolate_endpoint": u"/endpoint/v1/endpoints/isolation",
    u"get_alert_actions": u"/common/v1/alerts/{alert_id}",
    u"execute_alert_action": u"/common/v1/alerts/{alert_id}/actions",
    u"get_blocked_items": "/endpoint/v1/settings/blocked-items",
    u"add_to_blocklist": u"/endpoint/v1/settings/blocked-items",
    u"add_to_allowlist": u"/endpoint/v1/settings/allowed-items"
}

FILTER_ENTITY_TYPES = {
    EntityTypes.HOSTNAME: u"hostnameContains",
    EntityTypes.ADDRESS: u"ipAddresses"
}


class EndpointTypes(object):
    SERVER = u"server"
    COMPUTER = u"computer"


class SophosManager(object):

    def __init__(self, api_root=None, client_id=None, client_secret=None, verify_ssl=False,
                 siem_api_root=None, api_key=None, api_token=None,
                 siemplify=None, test_connectivity=False):
        """
        Connect to Sophos
        """
        self.api_root = self._get_adjusted_root_url(api_root)
        self.verify_ssl = verify_ssl
        self.sensitive_data = [sd for sd in [client_id, client_secret, api_key, api_token] if sd]
        self.session = SiemplifySession(sensitive_data_arr=self.sensitive_data)
        self.session.verify = self.verify_ssl
        self.parser = SophosParser()
        self.siemplify = siemplify
        self.login(client_id, client_secret, verify_ssl)
        if test_connectivity:
            self.test_connectivity()
        if siem_api_root or api_key or api_token:
            self.api_key = api_key
            self.api_token = api_token
            self.siem_api_root = self._get_adjusted_root_url(siem_api_root)
            if test_connectivity:
                self.test_siem_connectivity()

    @staticmethod
    def _get_adjusted_root_url(api_root):
        if api_root:
            return api_root[:-1] if api_root.endswith("/") else api_root
        raise SophosManagerError('"SIEM API Root" parameter is required when "API Key" or "Base 64 Auth Payload" provided')

    def login(self, client_id, client_secret, verify_ssl):
        """
        Set session headers, get API root and fetch cookies.
        :param client_id: {string} Client id
        :param client_secret: {string} Client Secret
        :param verify_ssl: {bool} Use SSL on HTTP request
        :return: {void}
        """
        url = u"{0}/api/v2/oauth2/token".format(
            API_ROOT,
        )

        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "token"
        }

        response = requests.post(
            url=url,
            data=data,
            verify=verify_ssl
        )

        self.validate_response(response, u"Unable to login. Check your credentials.")

        if MULTI_AUTH_INDICATOR_KEY in response.json().keys():
            raise SophosManagerError(
                u"Multi-factor Authentication(MFA) is enabled. Disable it or login with different user.")

        # Set Sophos headers for authentication
        token = self.parser.get_acces_token(response.json())
        self.session.headers = {
            "Authorization": "Bearer {}".format(token)
        }
        self.session.cookies = response.cookies
        url = u"{0}/whoami/v1".format(self.api_root)
        response = self.session.get(url)
        self.validate_response(response, u"Unable to login. Check your credentials.", test_response_json=True)
        # Get new API ROOT (region based)
        api_root_details = self.parser.build_api_root_details_obj(response.json())
        self.session.headers.update({
            "X-Tenant-ID": api_root_details.id
        })
        self.api_root = api_root_details.api_root

    def test_connectivity(self):

        params = {
            "pageSize": 1
        }
        response = self.session.get(url=self._get_full_url(u"test_connectivity"), params=params)
        self.validate_response(response, error_msg=u"Unable to connect to Sophos", test_response_json=True)

        return True

    def test_siem_connectivity(self):
        session = SiemplifySession(sensitive_data_arr=self.sensitive_data)
        session.verify = self.verify_ssl
        session.headers.update({
            u"Authorization": u"Basic {}".format(self.api_token),
            u"x-api-key": self.api_key
        })
        params = {
            "limit": 1
        }
        url = u"{0}/siem/v1/events".format(self.siem_api_root)
        response = session.get(url=url, params=params)
        self.validate_response(response, error_msg=u"Unable to connect to Sophos", test_response_json=True)

        return True

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urlparse.urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def _paginate_results(self, method, url, params=None, body=None, limit=None, err_msg=u"Unable to get results"):
        """
        Paginate the results of a request
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The url to send request to
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param limit: {int} The limit of the results to fetch
        :param err_msg: {str} The message to display on error
        :return: {list} List of results
        """
        if params is None:
            params = {}

        params.update({
            u"limit": max(limit, LIMIT_PER_REQUEST)
        })

        response = self.session.request(method, url, params=params, json=body)

        validate_api_response(response, err_msg)
        results = response.json().get(u"items", [])
        has_more = response.json().get(u"has_more", False)
        next_cursor = response.json().get(u"next_cursor", "")

        while has_more:
            params.update({
                u"cursor": next_cursor
            })

            response = self.session.request(method, url, params=params, json=body)
            validate_api_response(response, err_msg)
            has_more = response.json().get(u"has_more", False)
            next_cursor = response.json().get(u"next_cursor", "")
            results.extend(response.json().get(u"items", []))

        return results

    def get_alerts(self, existing_ids, limit, start_time):
        """
        Get alerts
        :param existing_ids: {list} The list of existing ids
        :param limit: {int} The limit for results
        :param start_time: {int} The start timestamp from where to fetch
        :return: {list} The list of filtered Alert objects
        """
        request_url = self._get_full_url(u"get_alerts")
        params = {
            u"from_date": str(start_time)[:-3]
        }
        alerts = self.parser.build_alerts_list(self._paginate_results(method='GET', url=request_url, params=params,
                                                                      limit=limit))

        filtered_alerts = filter_old_alerts(
            siemplify=self.siemplify, alerts=alerts, existing_ids=existing_ids, id_key="id"
        )
        return sorted(filtered_alerts, key=lambda alert: alert.when)[:limit]

    def get_all_computers(self):
        """
        Get all endpoints
        :return: {list} List of endpoints (dicts)
        """
        return self.get_all_endpoints_by_type(EndpointTypes.COMPUTER)

    def get_all_endpoints_by_type(self, endpoint_type):
        """
        Get all endpoints by a given type (Computer / Server)
        :param endpoint_type: {str} The type of the endpoints to fetch
        :return: {list} The found endpoints
        """
        url = u"{}/user-devices/v1/bulk-endpoints".format(
            self.api_root,
        )

        response = self.session.get(
            url=url,
            params={"endpoint_type": endpoint_type,
                    "limit": LIMIT,
                    'get_health_status': True
                    }
        )

        self.validate_response(response, u"Unable to list endpoints of type {}".format(endpoint_type))
        endpoints_info = response.json().get('endpoints', [])
        columns = response.json().get('columns', [])

        endpoints = []

        # Match endpoint values with endpoint columns
        for endpoint in endpoints_info:
            endpoints.append({full_key: endpoint[columns[full_key]] for full_key, key in columns.items()})

        for endpoint in endpoints:
            endpoint[u"endpoint_type"] = endpoint_type

        return endpoints

    def get_all_endpoints(self):
        return self.get_all_servers() + self.get_all_computers()

    def get_all_servers(self):
        """
        Get all endpoints
        :return: {list} List of endpoints (dicts)
        """
        return self.get_all_endpoints_by_type(EndpointTypes.SERVER)

    def get_server(self, server_id):
        """
        Get a server by ID
        :param server_id: {str} The id of the server
        :return: {dict} The server info
        """
        url = u"{}/servers/{}".format(
            self.api_root,
            server_id
        )

        response = self.session.get(
            url=url
        )

        self.validate_response(response, u"Unable to get server {}".format(server_id))
        return response.json()

    def get_computer(self, computer_id):
        """
        Get a computer by its ID
        :param computer_id: {str} The computer id
        :return: {dict} The found computer info
        """
        url = u"{}/user-devices/{}".format(
            self.api_root,
            computer_id
        )

        response = self.session.get(
            url=url
        )

        self.validate_response(response, u"Unable to get computer {}".format(computer_id))
        return response.json()

    def get_endpoint_by_ip(self, ip):
        """
        Get endpoint by ip
        :param ip: {str} The ip to filter by
        :return: {dict} The found endpoint
        """
        # Retrieve all endpoints and filter them (no filtering available in api)
        endpoints = self.get_all_endpoints()

        for endpoint in endpoints:
            if ip in endpoint.get('INFO_IP_V4', []):
                return endpoint

    def get_endpoint_by_name(self, name):
        """
        Get endpoint by name
        :param name: {str} The name to filter by
        :return: {dict} The found endpoint
        """
        # Retrieve all endpoints and filter them (no filtering available in api)
        endpoints = self.get_all_endpoints()

        for endpoint in endpoints:
            if endpoint.get('LABEL', "").lower() == name.lower():
                return endpoint

    def get_endpoint_by_hostname(self, hostname):
        """
        Get endpoint by hostname
        :param hostname: {str} The hostname to filter by
        :return: {dict} The found endpoint
        """
        # Retrieve all endpoints and filter them (no filtering available in api)
        endpoints = self.get_all_endpoints()

        for endpoint in endpoints:
            if endpoint.get('COMPUTER_NAME', "").lower() == hostname.lower():
                return endpoint

    def get_events_by_endpoint(self, endpoint_id, since=None, limit=None):
        """
        Get events log of an endpoint
        :param endpoint_id: {str} The endpoint's id
        :return: {list} List of events (dicts)
        """
        session = SiemplifySession(sensitive_data_arr=self.sensitive_data)
        session.verify = self.verify_ssl
        session.headers.update({
            u"Authorization": u"Basic {}".format(self.api_token),
            u"x-api-key": self.api_key
        })
        url = u"{}/siem/v1/events".format(
            self.siem_api_root,
        )

        params = {
            'endpoint': endpoint_id,
            'from_date': since,
            'limit': limit
        }

        params = {key: value for key, value in params.items() if value is not None}
        results, cursor, response = [], None, None

        while True:
            if response:
                if not cursor or (limit and len(results) > limit):
                    break
                params.update({"cursor": cursor})

            response = session.get(url=url, params=params)
            self.validate_response(response, u"Unable to get events of endpoint {}".format(endpoint_id))

            results.extend(self.parser.build_results(raw_json=response.json(), method="build_event_obj", data_key="items"))
            if not self.parser.has_endpoint_more_events(response.json()):
                break
            cursor = self.parser.get_next_cursor(response.json())

        return results[:limit] if limit else results

    def get_computer_services(self, computer_id):
        """
        Get services statuses of an computer
        :param computer_id: {str} The computer_id's id
        :return: {dict} The services statuses
        """
        url = u"{}/user-devices/{}".format(
            self.api_root,
            computer_id
        )

        response = self.session.get(
            url=url,
            params={
                'get_health_status': True
            },
        )

        self.validate_response(response, u"Unable to list services of computer {}".format(computer_id))
        services = response.json().get("status", {}).get(r"shs/service/detail", {})

        # Replace numeric statuses with human readable statuses
        for key, value in services.items():
            if value in KNOWN_SERVICES_STATUSES.keys():
                services[key] = KNOWN_SERVICES_STATUSES[value]

        return services

    def get_server_services(self, server_id):
        """
        Get services statuses of an server
        :param server_id: {str} The server's id
        :return: {dict} The services statuses
        """
        url = u"{}/servers/{}".format(
            self.api_root,
            server_id
        )

        response = self.session.get(
            url=url,
            params={
                'get_health_status': True
            },
        )

        self.validate_response(response, u"Unable to list services of server {}".format(server_id))
        services = response.json().get("status", {}).get(r"shs/service/detail", {})

        # Replace numeric statuses with human readable statuses
        for key, value in services.items():
            if value in KNOWN_SERVICES_STATUSES.keys():
                services[key] = KNOWN_SERVICES_STATUSES[value]

        return services

    def validate_response(self, response, error_msg=u"An error occurred", test_response_json=False):
        try:
            if response.status_code == 409:
                raise HashAlreadyOnBlocklist("Resource already exists.")

            response.raise_for_status()

        except HashAlreadyOnBlocklist:
            raise
        except requests.HTTPError as error:
            raise SophosManagerError(self.session.encode_sensitive_data(
                u"{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.content)
            ))
        if test_response_json:
            try:
                response.json()
            except Exception as error:
                raise SophosManagerError(error_msg, self.session.encode_sensitive_data(error))

    def find_entities(self, entity_identifier, entity_type):
        """
        Get endpoint by entity_identifier
        :param entity_identifier: {str} The entity identifier to filter by
        :param entity_type: {str} The entity type to filter by
        :return: {dict} The found endpoint
        """
        params = {
            FILTER_ENTITY_TYPES[entity_type]: entity_identifier
        }
        response = self.session.get(self._get_full_url("test_connectivity"), params=params)
        self.validate_response(response, u"Unable to find endpoint for entity {}".format(entity_identifier))

        endpoints = self.parser.build_results(raw_json=response.json(), method="build_endpoint_obj", data_key="items")
        return self.get_filtered_endpoint(endpoints, entity_type, entity_identifier)

    def add_hash_to_blocklist(self, hash_entity, comment):
        """
        Function that adds hashes to the blocklist
        :param hash_entity: {str} The hash entity that should be added to a blocklist
        :param comment: {str} Comment to add
        """
        payload = json.dumps({
        "type": "sha256",
        "properties": {
            "sha256": hash_entity
        },
        "comment": comment
        })
        response = self.session.post(self._get_full_url("add_to_blocklist"), data=payload)
        self.validate_response(response, u"Unable to add hash {} to blocklist.".format(hash_entity))

    def add_hash_to_allowlist(self, hash_entity, comment):
        """
        Function that adds hashes to the allowlist
        :param hash_entity: {str} The hash entity that should be added to a allowlist
        :param comment: {str} Comment to add
        """
        payload = json.dumps({
        "type": "sha256",
        "properties": {
            "sha256": hash_entity
        },
        "comment": comment
        })
        response = self.session.post(self._get_full_url("add_to_allowlist"), data=payload)
        self.validate_response(response, u"Unable to add hash {} to allowlist.".format(hash_entity))



    def get_filtered_endpoint(self, endpoints, entity_type, entity_identifier):
        """
        Filter endpoint by entity_identifier
        :param endpoints: {str} The endpoints for given entity identifier
        :param entity_identifier: {str} The entity identifier to filter by
        :param entity_type: {str} The entity type to filter by
        :return: {dict} The found endpoint
        """
        for endpoint in endpoints:
            if entity_type == EntityTypes.HOSTNAME and endpoint.hostname.lower() == entity_identifier.lower():
                return endpoint
            elif entity_type == EntityTypes.ADDRESS and entity_identifier in endpoint.ip_address:
                return endpoint

        return None

    def scan_endpoint(self, scan_id):
        """
        Initiate scan on an endpoint
        :param scan_id: The endpoint to scan
        :return {bool} True if successful, exception otherwise
        """
        response = self.session.get(self._get_full_url("initiate_scan", scan_id=scan_id))
        self.validate_response(response, u"Unable to scan endpoint {}".format(scan_id))

        return True

    def check_isolation_status(self, endpoint_id):
        """
        Check isolation status on an endpoint
        :param endpoint_id: The endpoint id
        :return {str} Isolation status
        """
        request_url = self._get_full_url(u"check_isolation_status", endpoint_id=endpoint_id)
        response = self.session.get(request_url)
        self.validate_response(response)

        response_json = response.json()

        if response_json.get("lastEnabledAt"):
            return ISOLATED
        elif response_json == UNISOLATED_JSON_RESPONSE:
            return UNISOLATED
        else:
            return ISOLATION_IN_PROGRESS

    def isolate_or_unisolate_endpoint(self, isolate, endpoint_id, comment):
        """
        Isolate or Unisolate the endpoint
        :param isolate: {bool} If True, will isolate, otherwise unisolate
        :param endpoint_id: {str} The id of the endpoint to isolate/unisolate
        :param comment: {str} Comment explaining the need of isolation/unisolation.
        :return {bool} True if successful, exception otherwise
        """
        request_url = self._get_full_url(u"isolate_endpoint")
        payload = {
            "enabled": isolate,
            "ids": [
                endpoint_id
            ],
            "comment": comment
        }
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)

    def get_alert_actions(self, alert_id):
        """
        Get alert actions
        :param alert_id: The alert id
        :return {list}
        """
        request_url = self._get_full_url(u"get_alert_actions", alert_id=alert_id)
        response = self.session.get(request_url)

        if response.status_code == 400:
            raise Exception(response.json().get("message"))
        elif response.status_code == 404:
            raise Exception(u"alert with ID {} was not found in Sophos".format(alert_id))
        self.validate_response(response)

        return response.json().get("allowedActions", [])

    def execute_alert_action(self, alert_id, action, message):
        """
        Execute alert action
        :param alert_id: {str} The alert id
        :param action: {str} Action to execute
        :param message: {str} Message explaining the reason
        :return {bool} True if successful, exception otherwise
        """
        request_url = self._get_full_url(u"execute_alert_action", alert_id=alert_id)
        payload = {
            "action": action,
            "message": message
        }
        response = self.session.post(request_url, json=payload)

        if response.status_code == 400:
            raise Exception(u"Invalid action was provided for the alert. Please check what actions are available for "
                            u"the provided alert with action \"List Alert Actions\".")
        elif response.status_code == 404:
            raise Exception(u"alert with ID {} was not found in Sophos".format(alert_id))
        self.validate_response(response)

    def get_blocked_items(self, entity_identifier):
        """
        Get alert actions
        :param entity_identifier: The entity identifier
        :return {FileHash}
        """
        request_url = self._get_full_url(u"get_blocked_items")
        response = self.session.get(request_url)
        self.validate_response(response)

        hashes = self.parser.build_results(
            raw_json=self._paginate_results_for_different_api(method='GET', url=request_url), method="build_hash_obj",
            pure_data=True
        )
        return self.get_filtered_hash(hashes, entity_identifier)

    def get_filtered_hash(self, hashes, entity_identifier):
        """
        Filter hash by entity_identifier
        :param hashes: {list} The hashes for given entity identifier
        :param entity_identifier: {str} The entity identifier to filter by
        :return: {FileHash} The found Hash object
        """
        for filehash in hashes:
            if filehash.hash_value.lower() == entity_identifier.lower():
                return filehash

    def _paginate_results_for_different_api(self, method, url, params=None, body=None, limit=None,
                                            err_msg=u"Unable to get results"):
        """
        Paginate the results of a request
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The url to send request to
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param limit: {int} The limit of the results to fetch
        :param err_msg: {str} The message to display on error
        :return: {list} List of results
        """
        if params is None:
            params = {}

        page_number = 1
        params.update({
            u"pageSize": LIMIT_PER_REQUEST,
            u"pageTotal": True,
            u"page": page_number
        })

        response = self.session.request(method, url, params=params, json=body)

        self.validate_response(response, err_msg)
        results = response.json().get(u"items", [])
        total_items = response.json().get(u"pages", {}).get("items")

        while total_items > len(results):
            page_number += 1
            params.update({
                u"page": page_number
            })

            response = self.session.request(method, url, params=params, json=body)
            self.validate_response(response, err_msg)
            total_items = response.json().get(u"pages", {}).get("items")
            results.extend(response.json().get(u"items", []))

        return results


class SophosManagerForConnector(object):

    def __init__(self, username=None, password=None, verify_ssl=False, api_root=None, api_key=None, api_token=None,
                 siemplify=None):
        """
        Connect to Sophos
        """
        self.api_root = ""
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.parser = SophosParser()
        self.siemplify = siemplify
        if username and password:
            self.login(username, password, verify_ssl)
        if api_root and api_key and api_token:
            self.api_root = api_root
            self.session.headers.update({
                u"Authorization": u"Basic {}".format(api_token),
                u"x-api-key": api_key
            })

    def login(self, username, password, verify_ssl):
        """
        Set session headers, get API root and fetch cookies.
        :param username: {string} Username
        :param password: {string} Username password
        :param verify_ssl: {bool} Use SSL on HTTP request
        :return: {void}
        """
        url = u"{0}/sessions".format(
            API_ROOT,
        )

        response = requests.post(
            url=url,
            headers={
                u'Authorization': u'Hammer {}'.format(
                    base64.b64encode(u"{}:{}".format(username, password)))
            },
            verify=verify_ssl
        )

        self.validate_response(response, u"Unable to login. Check your credentials.")

        if MULTI_AUTH_INDICATOR_KEY in response.json().keys():
            raise SophosManagerError(
                u"Multi-factor Authentication(MFA) is enabled. Disable it or login with different user.")

        # Set Sophos headers for authentication
        self.session.headers = {
            u'X-Hammer-Token': response.json()['token'],
            u'X-CSRF-Token': response.json()['csrf']
        }

        # Set cookies
        self.session.cookies = response.cookies

        # Get new API ROOT (region based)
        self.api_root = response.json()['apis']['upe']['ng_url']

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urlparse.urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def get_alerts(self, existing_ids, limit, start_time):
        """
        Get alerts
        :param existing_ids: {list} The list of existing ids
        :param limit: {int} The limit for results
        :param start_time: {int} The start timestamp from where to fetch
        :return: {list} The list of filtered Alert objects
        """
        request_url = self._get_full_url(u"get_alerts")
        params = {
            u"from_date": str(start_time)[:-3]
        }
        alerts = self.parser.build_alerts_list(self._paginate_results(method='GET', url=request_url, params=params,
                                                                      limit=limit))

        filtered_alerts = filter_old_alerts(
            siemplify=self.siemplify, alerts=alerts, existing_ids=existing_ids, id_key="id"
        )
        return sorted(filtered_alerts, key=lambda alert: alert.when)[:limit]

    @staticmethod
    def validate_response(response, error_msg=u"An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            # Not a JSON - return content
            raise SophosManagerError(
                u"{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.content)
            )

    def _paginate_results(self, method, url, params=None, body=None, limit=None, err_msg=u"Unable to get results"):
        """
        Paginate the results of a request
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The url to send request to
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param limit: {int} The limit of the results to fetch
        :param err_msg: {str} The message to display on error
        :return: {list} List of results
        """
        if params is None:
            params = {}

        params.update({
            u"limit": max(limit, LIMIT_PER_REQUEST)
        })

        response = self.session.request(method, url, params=params, json=body)

        validate_api_response(response, err_msg)
        results = response.json().get(u"items", [])
        has_more = response.json().get(u"has_more", False)
        next_cursor = response.json().get(u"next_cursor", "")

        while has_more:
            params.update({
                u"cursor": next_cursor
            })

            response = self.session.request(method, url, params=params, json=body)
            validate_api_response(response, err_msg)
            has_more = response.json().get(u"has_more", False)
            next_cursor = response.json().get(u"next_cursor", "")
            results.extend(response.json().get(u"items", []))

        return results