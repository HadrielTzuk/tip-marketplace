from typing import List
from urllib.parse import urljoin

import requests

from PhishrodParser import PhishrodParser
from SiemplifyLogger import SiemplifyLogger
from UtilsManager import validate_response
from constants import ENDPOINTS
from datamodels import Incident


class PhishrodManager:
    """
    Phishrod Integration API interaction class
    """
    def __init__(
        self,
        api_root: str,
        api_key: str,
        client_id: str,
        username: str,
        password: str,
        verify_ssl: bool,
        siemplify_logger: SiemplifyLogger = None,
    ):
        """
        The method is used to init an object of Manager class

        Args:
            api_root: API root of the Phishrod instance.
            api_key: API Key of the Phishrod account.
            client_id: Client ID of the Phishrod account.
            username: Username of the Phishrod account.
            password: Password of the Phishrod account.
            verify_ssl: If enabled, validate the SSL certificate for the connection to the Phishrod.
            siemplify_logger: Siemplify logger
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.api_key = api_key
        self.client_id = client_id
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.siemplify_logger = siemplify_logger
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = verify_ssl
        self.parser = PhishrodParser()

    def _get_full_url(self, url_id: str, **kwargs: str) -> str:
        """
        Get full url from url identifier.

        Args:
            url_id: The id of url.
            **kwargs: Variables passed for string formatting.

        Returns:
            The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self) -> bool:
        """
        Test connectivity

        Returns:
            None
        """
        url = self._get_full_url("ping", api_key=self.api_key, client_id=self.client_id)
        response = self.session.get(url)
        validate_response(response)
        return True

    def get_incidents(self) -> List[Incident]:
        """
        Fetches incident data from API and covers it into Incident dataclass

        Returns:
            List of Incident object
        """
        url = self._get_full_url("get_incidents", api_key=self.api_key, client_id=self.client_id)
        response = self.session.get(url)
        validate_response(response)
        return self.parser.get_results(response.json(), "build_incidents")
