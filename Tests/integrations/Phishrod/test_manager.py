import json
import unittest

import pytest

from Integrations.Phishrod.Managers.PhishrodExceptions import PhishrodException
from Integrations.Phishrod.Managers.PhishrodManager import PhishrodManager
from Integrations.Phishrod.Managers.datamodels import Incident
from Tests.integrations.LoggerMock import Logger


class TestPhishrodManager(unittest.TestCase):
    """
    PhishrodManager test cases
    """

    def setUp(self) -> None:
        with open("config.json", "r", encoding="utf-8") as config_file:
            config = json.load(config_file)

        api_root = config.get("api_root")
        api_key = config.get("api_key")
        client_id = config.get("client_id")
        username = config.get("username")
        password = config.get("password")
        verify_ssl = config.get("verify_ssl")
        self.manager = PhishrodManager(
            api_root=api_root,
            api_key=api_key,
            client_id=client_id,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            siemplify_logger=Logger(),
        )

    def test_connectivity_success(self) -> None:
        """
        Test connectivity success

        Returns:
            None
        """
        self.assertTrue(self.manager.test_connectivity())

    @pytest.mark.usefixtures("mock_test_connectivity_to_raise_manager_error")
    def test_connectivity_failure(self) -> None:
        """
        Test connectivity failure

        Returns:
            None
        """
        with pytest.raises(PhishrodException):
            self.manager.test_connectivity()

    def test_get_incidents(self) -> None:
        """
        Test get incidents

        Returns:
            None
        """
        incidents = self.manager.get_incidents()
        for incident in incidents:
            assert isinstance(incident, Incident)

    @pytest.mark.usefixtures("mock_get_incidents_to_raise_manager_error")
    def test_get_incidents_failure(self) -> None:
        """
        Test get incidents failure

        Returns:
            None
        """
        with pytest.raises(PhishrodException):
            self.manager.get_incidents()
