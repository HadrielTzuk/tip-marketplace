from __future__ import annotations
import json
import unittest
import pytest
import TrendMicroDDANExceptions
from Integrations.TrendMicroDDAN.Managers.TrendMicroDDANManager import TrendMicroDDANManager
from Integrations.TrendMicroDDAN.Managers.TrendMicroDDANExceptions import TrendMicroDDANException
from Integrations.TrendMicroDDAN.Managers.UtilsManager import get_string_sha1
from Integrations.TrendMicroDDAN.Managers.constants import SAMPLE_TYPE
from datamodels import Report, EventLog, SuspiciousObject

FILE_URL = "https://www.clickdimensions.com/links/TestPDFfile.pdf"
LIMIT = 1


class TestTrendMicroDDANManager(unittest.TestCase):
    def setUp(self) -> None:
        with open("config.json", "r") as f:
            data = f.read()

        config = json.loads(data)

        api_root = config.get("api_root")
        api_key = config.get("api_key")
        verify_ssl = config.get("verify_ssl")

        self.manager = TrendMicroDDANManager(
            api_root,
            api_key,
            verify_ssl
        )

    def test_connectivity_success(self) -> None:
        """
        Test for connectivity success
        Returns:
            None
        """
        self.manager.register()
        result = self.manager.test_connectivity()
        self.manager.unregister()
        assert result is None

    @pytest.mark.usefixtures("mock_test_connectivity_to_raise_manager_error")
    def test_connectivity_fail(self) -> None:
        """
        Test for connectivity failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.test_connectivity()

    def test_register_success(self) -> None:
        """
        Test for register success
        Returns:
            None
        """
        result = self.manager.register()
        self.manager.unregister()
        assert result is None

    @pytest.mark.usefixtures("mock_register_to_raise_manager_error")
    def test_register_fail(self) -> None:
        """
        Test for register failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.register()

    def test_unregister_success(self) -> None:
        """
        Test for unregister success
        Returns:
            None
        """
        self.manager.register()
        assert self.manager.unregister() is None

    @pytest.mark.usefixtures("mock_unregister_to_raise_manager_error")
    def test_unregister_fail(self) -> None:
        """
        Test for unregister failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.unregister()

    def test_check_duplicate_success(self) -> None:
        """
        Test for check duplicate success
        Returns:
            None
        """
        self.manager.register()
        result = self.manager.check_duplicate(FILE_URL)
        self.manager.unregister()
        assert isinstance(result, str)

    @pytest.mark.usefixtures("mock_check_duplicate_to_raise_manager_error")
    def test_check_duplicate_fail(self) -> None:
        """
        Test for check duplicate failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.check_duplicate(FILE_URL)

    def test_submit_sample_success(self) -> None:
        """
        Test for submit sample success
        Returns:
            None
        """
        self.manager.register()
        result = self.manager.submit_sample(get_string_sha1(FILE_URL), SAMPLE_TYPE.get("url"), FILE_URL)
        self.manager.unregister()
        assert result is None

    @pytest.mark.usefixtures("mock_submit_sample_to_raise_manager_error")
    def test_submit_sample_fail(self) -> None:
        """
        Test for submit sample failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.submit_sample(get_string_sha1(FILE_URL), SAMPLE_TYPE.get("url"), FILE_URL)

    def test_get_report_success(self) -> None:
        """
        Test for get report success
        Returns:
            None
        """
        self.manager.register()
        try:
            assert isinstance(self.manager.get_report(FILE_URL), Report)
        except TrendMicroDDANExceptions.TrendMicroDDANInProgressException:
            pass
        finally:
            self.manager.unregister()

    @pytest.mark.usefixtures("mock_get_report_to_raise_manager_error")
    def test_get_report_fail(self) -> None:
        """
        Test for get report failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.get_report(FILE_URL)

    def test_get_event_logs_success(self) -> None:
        """
        Test for get event logs success
        Returns:
            None
        """
        self.manager.register()
        results = self.manager.get_event_logs(FILE_URL, LIMIT)
        self.manager.unregister()
        assert isinstance(results, list)

        for result in results:
            assert isinstance(result, EventLog)

    @pytest.mark.usefixtures("mock_get_event_logs_to_raise_manager_error")
    def test_get_event_logs_fail(self) -> None:
        """
        Test for get event logs failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.get_event_logs(FILE_URL, LIMIT)

    def test_get_suspicious_objects_success(self) -> None:
        """
        Test for get suspicious objects success
        Returns:
            None
        """
        self.manager.register()
        try:
            results = self.manager.get_suspicious_objects(FILE_URL, LIMIT)
            assert isinstance(results, list)

            for result in results:
                assert isinstance(result, SuspiciousObject)

        except TrendMicroDDANExceptions.TrendMicroDDANNotFoundException:
            pass
        finally:
            self.manager.unregister()

    @pytest.mark.usefixtures("mock_get_suspicious_objects_to_raise_manager_error")
    def test_get_suspicious_objects_fail(self) -> None:
        """
        Test for get suspicious objects failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.get_suspicious_objects(FILE_URL, LIMIT)

    def test_get_screenshot_success(self) -> None:
        """
        Test for get screenshot success
        Returns:
            None
        """
        self.manager.register()
        try:
            result = self.manager.get_screenshot(FILE_URL)
            assert isinstance(result, str)

        except TrendMicroDDANExceptions.TrendMicroDDANNotFoundException:
            pass
        finally:
            self.manager.unregister()

    @pytest.mark.usefixtures("mock_get_screenshot_to_raise_manager_error")
    def test_get_screenshot_fail(self) -> None:
        """
        Test for get screenshot failure
        Returns:
            None
        """
        with pytest.raises(TrendMicroDDANException):
            self.manager.get_screenshot(FILE_URL)

