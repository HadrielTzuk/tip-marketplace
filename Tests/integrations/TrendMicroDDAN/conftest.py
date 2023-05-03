from Integrations.TrendMicroDDAN.Managers.TrendMicroDDANManager import TrendMicroDDANManager
from Integrations.TrendMicroDDAN.Managers.TrendMicroDDANExceptions import TrendMicroDDANException
import pytest
from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture
def mock_test_connectivity_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred: 401 Client Error")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'test_connectivity',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_register_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'register',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_unregister_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'unregister',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_check_duplicate_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'check_duplicate',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_submit_sample_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'submit_sample',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_get_report_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'get_report',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_get_event_logs_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'get_event_logs',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_get_suspicious_objects_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'get_suspicious_objects',
        mock_raise_manager_error
    )


@pytest.fixture
def mock_get_screenshot_to_raise_manager_error(monkeypatch: MonkeyPatch) -> None:
    def mock_raise_manager_error(*args, **kwargs) -> None:
        raise TrendMicroDDANException("An error occurred")

    monkeypatch.setattr(
        TrendMicroDDANManager,
        'get_screenshot',
        mock_raise_manager_error
    )
