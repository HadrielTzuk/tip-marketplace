from urllib.parse import urljoin
import requests
from constants import ENDPOINTS, DEFAULT_LIMIT, ALERT_ID_KEY
from TIPCommon import filter_old_alerts
from UtilsManager import validate_response
from ExtrahopParser import ExtrahopParser


class ExtrahopManager:
    def __init__(self, api_root, client_id, client_secret, verify_ssl, siemplify=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} API root of the Extrahop instance
        :param client_id: {str} Client ID of the Extrahop instance
        :param client_secret: {str} Client Secret of the Extrahop instance
        :param verify_ssl: {bool} Specifies if certificate that is configured on the api root should be validated
        :param siemplify: Siemplify Connector Executor
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.siemplify = siemplify
        self.parser = ExtrahopParser()
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.auth = (client_id, client_secret)
        self.session.headers.update({"Authorization": f"Bearer {self.get_auth_token()}"})
        self.session.auth = None

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def get_auth_token(self):
        url = self._get_full_url("token")
        payload = {
            "grant_type": "client_credentials"
        }
        response = self.session.post(url, data=payload)
        validate_response(response)
        return response.json().get("access_token")

    def test_connectivity(self):
        """
        Test connectivity
        """
        url = self._get_full_url("ping")
        response = self.session.get(url)
        validate_response(response)

    def get_detections(self, existing_ids, limit, start_timestamp):
        """
        Get detections
        :param existing_ids: {list} The list of existing ids
        :param limit: {int} The limit for results
        :param start_timestamp: {datetime} The timestamp for oldest detection to fetch
        :return: {list} The list of filtered Detection objects
        """
        request_url = self._get_full_url("get_detections")
        payload = {
            "sort": [{
                "direction": "asc",
                "field": "update_time"
            }],
            "filter": {
                "status": ["new", "in_progress", ".none"]
            },
            "update_time": start_timestamp,
            "limit": max(limit, DEFAULT_LIMIT)
        }
        response = self.session.post(request_url, json=payload)
        validate_response(response)
        detections = self.parser.build_detections_list(response.json())

        filtered_detections = filter_old_alerts(siemplify=self.siemplify, alerts=detections,
                                                existing_ids=existing_ids, id_key=ALERT_ID_KEY)
        return sorted(filtered_detections, key=lambda detection: detection.update_time)[:limit]

    def get_device_details(self, device_id):
        """
        Get device details
        :param device_id: {int} Id of the device
        :return: {Device}
        """
        request_url = self._get_full_url("get_device_details", device_id=device_id)
        response = self.session.get(request_url)
        validate_response(response)
        return self.parser.build_device(response.json())
