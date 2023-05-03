from urllib.parse import urljoin
from UtilsManager import validate_response, parse_string_to_dict, datetime_to_rfc3339, validate_request_id
from GoogleSecurityCommandCenterParser import GoogleSecurityCommandCenterParser
from constants import ENDPOINTS, SCOPES
from google.oauth2 import service_account
from googleapiclient import _auth
import json
import datetime


class GoogleSecurityCommandCenterManager:
    def __init__(self, api_root, service_account_string, verify_ssl, organization_id=None, siemplify_logger=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} API root
        :param organization_id: {str} organization id
        :param service_account_string: {str} JSON string containing service account info
        :param verify_ssl: {bool} Specifies if certificate that is configured on the api root should be validated
        :param siemplify_logger: Siemplify logger
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.organization_id = organization_id
        self.service_account_string = service_account_string
        self.service_account_json = parse_string_to_dict(self.service_account_string)
        self.verify_ssl = verify_ssl
        self.project_id = self.service_account_json.get('project_id', '')
        self.request_level_type = 'organizations' if self.organization_id else 'projects'
        self.request_level_id = self.organization_id if self.organization_id else self.project_id
        validate_request_id(self.request_level_id)
        self.siemplify_logger = siemplify_logger
        self.parser = GoogleSecurityCommandCenterParser()
        self.http_client = None
        self._prepare_http_client()

    def _prepare_http_client(self):
        """
        Prepare http client
        :return: {void}
        """
        credentials = service_account.Credentials.from_service_account_info(self.service_account_json, scopes=SCOPES)
        self.http_client = _auth.authorized_http(credentials)
        self.http_client.http.disable_ssl_certificate_validation = not self.verify_ssl

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity
        :return: {void}
        """
        url = self._get_full_url("ping", type=self.request_level_type, id=self.request_level_id)
        response_info, content = self.http_client.request(url, "GET")
        validate_response(response_info, content)

    def get_finding_details(self, finding_name):
        """
        Get finding details
        :param finding_name: {str} Name of the finding
        :return: {list} List of FindingDetails objects
        """
        url = self._get_full_url("get_finding_details", type=self.request_level_type, id=self.request_level_id,
                                 finding_name=finding_name)
        response_info, content = self.http_client.request(url, "GET")
        validate_response(response_info, content)

        return self.parser.build_finding_details_list(json.loads(content))

    def get_alerts(self, finding_class_filter, category_filter, severity_filter, event_time_filter):
        url = self._get_full_url(
            "get_alerts", type=self.request_level_type, id=self.request_level_id,
            finding_class_filter=finding_class_filter,
            category_filter=category_filter,
            severity_filter=severity_filter,
            event_time_filter=event_time_filter,
            page_size=100
        )
        self.siemplify_logger.info(f"Get alerts full query: {url}")

        response_info, content = self.http_client.request(url, "GET")
        validate_response(response_info, content)

        return self.parser.build_alerts_details_list(json.loads(content))

    def get_vulnerabilities(self, resource_name, timestamp, limit):
        """
        Get vulnerabilities
        :param resource_name: {str} Name of the resource
        :param timestamp: {int} Timestamp to fetch from
        :param limit: {int} Results limit
        :return: {list} List of FindingDetails objects
        """
        time_filter = f"AND eventTime >= {timestamp} " if timestamp else ""
        url = self._get_full_url("get_vulnerabilities", type=self.request_level_type, id=self.request_level_id,
                                 resource_name=resource_name,
                                 time_filter=time_filter)
        response_info, content = self.http_client.request(url, "GET")
        validate_response(response_info, content)
        results = self.parser.build_finding_details_list(json.loads(content))
        return sorted(results, key=lambda finding: finding.get_severity(), reverse=True)[:limit]

    def get_misconfigurations(self, resource_name, timestamp, limit):
        """
        Get misconfigurations
        :param resource_name: {str} Name of the resource
        :param timestamp: {int} Timestamp to fetch from
        :param limit: {int} Results limit
        :return: {list} List of FindingDetails objects
        """
        time_filter = f"AND eventTime >= {timestamp} " if timestamp else ""
        url = self._get_full_url("get_misconfigurations", type=self.request_level_type, id=self.request_level_id,
                                 resource_name=resource_name,
                                 time_filter=time_filter)
        response_info, content = self.http_client.request(url, "GET")
        validate_response(response_info, content)
        results = self.parser.build_finding_details_list(json.loads(content))
        return sorted(results, key=lambda finding: finding.get_severity(), reverse=True)[:limit]

    def get_asset_details(self, resource_names):
        """
        Get asset details by resource names
        :param resource_names: {[str]} list of resource names for filtering
        :return: {[Asset]} list of Asset objects
        """
        filter_string = f'securityCenterProperties.resourceName='
        filter_string += ' OR securityCenterProperties.resourceName='.join([f'"{name}"'for name in resource_names])
        url = self._get_full_url("get_asset_details", type=self.request_level_type, id=self.request_level_id,
                                 page_size=100, filter=filter_string)
        response_info, content = self.http_client.request(url, "GET")
        validate_response(response_info, content)

        return self.parser.build_asset_objects(json.loads(content))

    def change_mute_status(self, finding_name, mute_status):
        """
        Change mute status
        :param finding_name: {str} Name of the finding
        :param mute_status: {str} Mute status
        :return: {FindingDetails}
        """
        url = self._get_full_url("change_mute_status", finding_name=finding_name)
        json_data = json.dumps({"mute": mute_status})
        response_info, content = self.http_client.request(url, "POST", json_data)
        validate_response(response_info, content)

        return self.parser.build_finding_details_object(json.loads(content))

    def change_state_status(self, finding_name, state_status):
        """
        Change state status
        :param finding_name: {str} Name of the finding
        :param state_status: {str} State status
        :return: {FindingDetails}
        """
        url = self._get_full_url("change_state_status", finding_name=finding_name)
        json_data = json.dumps({"state": state_status, "startTime": datetime_to_rfc3339(datetime.datetime.now())})
        response_info, content = self.http_client.request(url, "POST", json_data)
        validate_response(response_info, content)

        return self.parser.build_finding_details_object(json.loads(content))
