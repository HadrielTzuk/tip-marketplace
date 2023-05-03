from urllib.parse import urljoin
import requests
from constants import ENDPOINTS, CA_CERTIFICATE_FILE_PATH
from UtilsManager import validate_response
from SplashParser import SplashParser
from SplashExceptions import EntityNotFoundException


class SplashManager:
    def __init__(self, api_root, verify_ssl=False, siemplify_logger=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} API root of the Splash instance.
        :param verify_ssl: {bool} If enabled, verify the SSL certificate for the connection to the Splash server is valid.
        :param siemplify_logger: Siemplify logger
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.logger = siemplify_logger
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.parser = SplashParser()

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
        """
        request_url = self._get_full_url("ping")
        response = self.session.get(request_url)
        validate_response(response)

    def get_entity_data(self, identifier, include_history, include_har):
        """
        Get details about entity
        :param identifier: {str} Entity identifier
        :param include_history: {bool} If True, will return history
        :param include_har: {bool} If True, will return HAR
        :return: Address object
        """
        request_url = self._get_full_url("get_data")
        params = {
            "url": identifier,
            "history": int(include_history),
            "har": int(include_har),
            "png": 1
        }
        response = self.session.get(request_url, params=params)
        if response.status_code in [502, 504]:
            raise EntityNotFoundException(response.content)
        validate_response(response)

        return self.parser.build_address_object(response.json())
