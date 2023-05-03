from __future__ import annotations

import json
import unittest
from typing import List
from unittest.mock import patch

import pytest
from _pytest.monkeypatch import MonkeyPatch

from datamodels import Company, VulnerabilityStats
from Integrations.BitSight.Managers.BitSightManager import BitSightManager
from Integrations.BitSight.Managers.BitSightExceptions import BitSightException

# from Tests.integrations.BitSight.conftest import (
#     mock_get_companies_response,
#     mock_get_vulnerabilities_response
#
from Tests.integrations.LoggerMock import Logger


################################################
#       Class based approach - Unittests       #
################################################


class TestBitsightManager(unittest.TestCase):
    def setUp(self) -> None:
        with open("config.json", "r") as f:
            data = f.read()

        config = json.loads(data)
        api_root = config.get("api_root")
        api_key = config.get("api_key")
        verify_ssl = config.get("verify_ssl")
        self.manager = BitSightManager(
            api_root=api_root,
            api_key=api_key,
            verify_ssl=verify_ssl,
            siemplify_logger=Logger()
        )
        self.test_company_id = self._get_test_company_id()

    def _get_test_company_id(self) -> str:
        companies = self.manager.get_companies()
        return companies[0].guid if len(companies) else ""

    def test_connectivity_success(self) -> None:
        """
        Test for connectivity success
        Args:
            bitsight_manager: BitSightManager
        Returns:
            None
        """
        assert self.manager.test_connectivity() is None  # no exception were raised

    @pytest.mark.usefixtures("mock_test_connectivity_to_raise_manager_error")
    def test_connectivity_fail(self) -> None:
        """
            Test for connectivity failure
            Args:
                bitsight_manager: BitSightManager
            Returns:
                None
            """
        with pytest.raises(BitSightException):
            self.manager.test_connectivity()

    # @patch(
    #     "Integrations.BitSight.Managers.BitSightManager.requests.Session.get",
    #     side_effect=mock_get_companies_response
    # )
    # @patch("Integrations.BitSight.Managers.BitSightManager.validate_response", return_value=True)
    def test_get_companies(self, *args) -> None:
        companies = self.manager.get_companies()
        assert isinstance(companies, list)
        if len(companies):  # companies list can be empty
            assert isinstance(companies[0], Company)

    # @patch(
    #     "Integrations.BitSight.Managers.BitSightManager.requests.Session.get",
    #     side_effect=mock_get_companies_response
    # )
    # @patch("Integrations.BitSight.Managers.BitSightManager.validate_response", return_value=True)
    def test_get_company_details_success(self, *args) -> None:
        if self.test_company_id:  # companies list can be empty
            company = self.manager.get_company_details(self.test_company_id)
            assert isinstance(company, Company)

    @pytest.mark.usefixtures("mock_get_company_details_raise_manager_error")
    def test_get_company_details_incorrect_company_id(self, *args) -> None:
        company_id = "dummy_id"
        with pytest.raises(BitSightException):
            self.manager.get_company_details(company_id)

    # @patch(
    #     "Integrations.BitSight.Managers.BitSightManager.requests.Session.get",
    #     side_effect=mock_get_vulnerabilities_response
    # )
    # @patch("Integrations.BitSight.Managers.BitSightManager.validate_response", return_value=True)
    def test_get_company_vulnerabilities_success(self, *args) -> None:
        if self.test_company_id:  # companies list can be empty
            vulnerabilities = self.manager.get_company_vulnerabilities(self.test_company_id, high_confidence=False)
            assert isinstance(vulnerabilities[0], VulnerabilityStats)

    @pytest.mark.usefixtures("mock_get_company_vulnerabilities_raise_manager_error")
    def test_get_company_vulnerabilities_incorrect_company_id(self, *args) -> None:
        company_id = "dummy_id"
        with pytest.raises(BitSightException):
            self.manager.get_company_vulnerabilities(company_id, high_confidence=False)

    def test_get_company_vulnerabilities_high_confidence(self, *args) -> None:
        if self.test_company_id:
            stats: List[VulnerabilityStats] = self.manager.get_company_vulnerabilities(
                self.test_company_id, high_confidence=True
            )
            for vulnerability in stats[0].vulnerabilities:
                self.assertEquals(vulnerability.confidence, "HIGH")
            assert isinstance(stats[0], VulnerabilityStats)


################################################
#       Function based approach - pytest       #
################################################


def test_connectivity_success(bitsight_manager) -> None:
    """
    Test for connectivity success
    Args:
        bitsight_manager: BitSightManager
    Returns:
        None
    """
    assert bitsight_manager.test_connectivity() is None  # no exception were raised


def test_connectivity_fail(
        bitsight_manager, mock_test_connectivity_to_raise_manager_error: MonkeyPatch
) -> None:
    """
        Test for connectivity failure
        Args:
            bitsight_manager: BitSightManager
        Returns:
            None
        """
    with pytest.raises(BitSightException):
        bitsight_manager.test_connectivity()


@patch("Integrations.BitSight.Managers.BitSightManager.validate_response", return_value=True)
def test_get_companies(
    bitsight_manager,
    mock_get_companies_response_pytest: MonkeyPatch,
) -> None:
    """
    Test for getting companies
    Args:
        bitsight_manager: BitSightManager
    Returns:
        None
    """
    companies = bitsight_manager.get_companies()
    assert isinstance(companies[0], Company)


def test_get_company_details(
    bitsight_manager,
) -> None:
    """
    Test for getting companies
    Args:
        bitsight_manager: BitSightManager
    Returns:
        None
    """
    company = bitsight_manager.get_company_details(company_id='a940bb61-33c4-42c9-9231-c8194c305db3')
    assert isinstance(company, Company)


def test_get_company_highlights(bitsight_manager) -> None:
    pass


def test_get_company_highlights_wrong_company(
        bitsight_manager
) -> None:
    pass


def test_get_company_vulnerabilities(bitsight_manager) -> None:
    pass


def test_get_alerts(bitsight_manager) -> None:
    pass


def test_get_findings(bitsight_manager) -> None:
    pass
