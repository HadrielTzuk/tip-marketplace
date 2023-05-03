import requests
from urllib.parse import urljoin

from TIPCommon import filter_old_alerts

from constants import ENDPOINTS, AUTH_URL, API_TIME_FORMAT, RISK_DETECTION_ID_FIELD
from AzureADIdentityProtectionParser import AzureADIdentityProtectionParser
from UtilsManager import validate_response


class AzureADIdentityProtectionManager:
    def __init__(self, api_root, client_id, client_secret, tenant_id, verify_ssl, siemplify=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} API root of the Azure AD Identity Protection instance
        :param client_id: {str} Client ID of the Azure AD Identity Protection account
        :param client_secret: {str} Client Secret of the Azure AD Identity Protection account
        :param tenant_id: {str} Tenant ID of the Azure AD Identity Protection account
        :param verify_ssl: {bool} Specifies if certificate that is configured on the api root should be validated
        :param siemplify_logger: Siemplify logger
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.verify_ssl = verify_ssl
        self.siemplify = siemplify
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.set_auth_token()
        self.parser = AzureADIdentityProtectionParser()

    def set_auth_token(self):
        """
        Set Authorization header to request session.
        """
        self.session.headers.update({"Authorization": "Bearer {}".format(self.get_auth_token())})

    def get_auth_token(self):
        """
        Send request in order to generate token.
        :return: {str} The authorization token
        """
        url = AUTH_URL.format(self.tenant_id)
        
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default"
        }
        
        response = self.session.post(url, data=payload)
        validate_response(response)
        return response.json().get("access_token")

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param root_url: {str} The API root for the request
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity
        """
        request_url = self._get_full_url("ping")
        response = self.session.get(request_url)
        validate_response(response)

    def get_user(self, username, filter_key):
        """
        Get a machine by its GUID
        :param username: {str} The name/email of the user to fetch
        :param filter_key: {str} Key to use for filtering
        :return: {User} User Object
        """
        request_url = self._get_full_url("get_users")
        params = {
            "$filter": f"{filter_key} eq \'{username}\'"
        }
        response = self.session.get(request_url, params=params)
        validate_response(response, "Unable to get user")

        return self.parser.build_user_object(response.json().get("value"))

    def update_user_state(self, user_id, compromise):
        """
        Update state of the user
        :param user_id: {str} The id of the user
        :param compromise: {bool} Whether to compromise or to dismiss
        """
        request_url = self._get_full_url("compromise") if compromise else self._get_full_url("dismiss")
        payload = {
            "userIds": [user_id]
        }
        response = self.session.post(request_url, json=payload)
        validate_response(response, "Unable to update user state")

    def get_risk_detections(self, existing_ids, limit, start_timestamp, lowest_severity):
        """
        Get alerts
        :param existing_ids: {list} The list of existing ids
        :param limit: {int} The limit for results
        :param start_timestamp: {datetime} The timestamp for oldest detection to fetch
        :param lowest_severity: {str} Lowest severity to fetch
        :return: {list} The list of filtered Risk Detection objects
        """
        request_url = self._get_full_url("get_alerts")
        query_string = self._build_query_string([
            self._build_time_filter(start_timestamp),
            self._build_severity_filter(lowest_severity),
            self._build_risk_state_filter()
        ])
        params = {
            "$filter": query_string,
            "$top": limit
        }
        response = self.session.get(request_url, params=params)
        validate_response(response)
        detections = self.parser.build_risk_detections_list(response.json())

        filtered_detections = filter_old_alerts(
            siemplify=self.siemplify,
            alerts=detections,
            existing_ids=existing_ids,
            id_key=RISK_DETECTION_ID_FIELD
        )
        return sorted(filtered_detections, key=lambda detection: detection.detected_date_time)[:limit]

    @staticmethod
    def _build_time_filter(start_time):
        """
        Build time filter.
        :param start_time: {datetime} Time for oldest detection to fetch.
        :return: {str} The query for time filter
        """
        return f'detectedDateTime ge {start_time.strftime(API_TIME_FORMAT)}'

    @staticmethod
    def _build_severity_filter(lowest_severity):
        """
        Build severity filter.
        :param lowest_severity: {str} Lowest severity to fetch
        :return: {str} The query for severity filter
        """
        return f"riskLevel ge \'{lowest_severity}\'" if lowest_severity else ""

    @staticmethod
    def _build_risk_state_filter():
        """
        Build risk state filter.
        :return: {str} The query for risk state filter
        """
        return "(riskState eq \'atRisk\' or riskState eq \'confirmedCompromised\')"

    @staticmethod
    def _build_query_string(queries):
        """
        Join filters.
        :param queries: {list} List of queries.
        :return: {str} Concatenated query
        """
        return f' and '.join([query for query in queries if query])
