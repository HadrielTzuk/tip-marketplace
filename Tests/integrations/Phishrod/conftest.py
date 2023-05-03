"""
Tests configuration file
"""
import pytest
from _pytest.monkeypatch import MonkeyPatch

from Integrations.Phishrod.Managers.PhishrodExceptions import PhishrodException
from Integrations.Phishrod.Managers.PhishrodManager import PhishrodManager


@pytest.fixture
def mock_test_connectivity_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    """
    Mock the test connectivity function to raise phishrod exception
    """

    def mock_raise_manager_error(*args: list, **kwargs: dict) -> None:
        raise PhishrodException("Connectivity error")

    monkeypatch.setattr(
        PhishrodManager,
        "test_connectivity",
        mock_raise_manager_error,
    )


@pytest.fixture
def mock_get_incidents_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    """
    Mock the get incidents function to raise phishrod exception
    """

    def mock_raise_manager_error(*args: list, **kwargs: dict) -> None:
        raise PhishrodException("Get incidents error")

    monkeypatch.setattr(
        PhishrodManager,
        "get_incidents",
        mock_raise_manager_error,
    )
