import datetime
import pytest
import warnings

from Integrations.TrendMicroVisionOne.Managers.TrendMicroVisionOneManager import TrendMicroVisionOneManager
from Integrations.TrendMicroVisionOne.Managers.constants import (
    ENDPOINTS,
    POSSIBLE_SEVERITIES,
    DEFAULT_MAX_LIMIT,
    SUCCESS_STATUS,
    FAILED_STATUS,
    REJECTED_STATUS,
)
from datamodels import Alert

from Tests.integrations.TrendMicroVisionOne.conftest import manager_fixture


DEFAULT_TIMESTAMP = 1
LOWEST_SEVERITY = "low"
DEFAULT_LIMIT = 10
DEFAULT_DESCRIPTION = "test description"
IN_PROGRESS_STATUS = "running"
DEFAULT_NUMBER_OF_ALERTS_FOR_TEST = 3
POSSIBLE_WORKBENCH_STATUSES = (
    "In Progress",
    "True Positive",
    "False Positive",
    "New",
)
TEST_SCRIPT_NAMES = (
    "security-playbook-CVE-2021-44142.sh",
    "hostname.sh"
)

class TestTrendMicroVisionOneManager:

    # Write tests to cover get_alerts method of TrendMicroVisionOneManager using pytest. Do not use mocks, use real API calls.
    def test_get_alerts(self, manager_fixture: TrendMicroVisionOneManager):
        alerts = manager_fixture.get_alerts(
            start_timestamp=DEFAULT_TIMESTAMP,
            lowest_severity_filter=LOWEST_SEVERITY,
            limit=DEFAULT_LIMIT
        )
        assert isinstance(alerts, list)

        if len(alerts) <= 0:
            warnings.warn("There are no alerts in the system. TEST RESULTS MAY BE INACCURATE.")

        assert all(isinstance(alert, Alert) for alert in alerts)

    @pytest.mark.parametrize("severity", POSSIBLE_SEVERITIES)
    def test_get_alerts_by_severity(self, manager_fixture: TrendMicroVisionOneManager, severity: str):
        alerts = manager_fixture.get_alerts(
            start_timestamp=DEFAULT_TIMESTAMP,
            lowest_severity_filter=severity,
            limit=DEFAULT_LIMIT
        )
        assert isinstance(alerts, list)

        if len(alerts) <= 0:
            warnings.warn("There are no alerts in the system. TEST RESULTS MAY BE INACCURATE.")

        assert all(isinstance(alert, Alert) for alert in alerts)

        allowed_severities = POSSIBLE_SEVERITIES[POSSIBLE_SEVERITIES.index(severity):]
        assert all(alert.severity in allowed_severities for alert in alerts)

    @pytest.mark.parametrize("offset_in_days", [1, 7, 30, 60])
    def test_get_alerts_by_timestamp(self, manager_fixture: TrendMicroVisionOneManager, offset_in_days: int):
        timestamp = int((datetime.datetime.now() - datetime.timedelta(days=offset_in_days)).timestamp())

        alerts = manager_fixture.get_alerts(
            start_timestamp=timestamp,
            lowest_severity_filter=LOWEST_SEVERITY,
            limit=DEFAULT_LIMIT
        )
        assert isinstance(alerts, list)

        if len(alerts) <= 0:
            warnings.warn("There are no alerts in the system. TEST RESULTS MAY BE INACCURATE.")

        assert all(isinstance(alert, Alert) for alert in alerts)
        assert all(alert.created_datetime >= timestamp for alert in alerts)

    @pytest.mark.parametrize("limit", [1, 11, 101])
    def test_get_alerts_by_limit(self, manager_fixture: TrendMicroVisionOneManager, limit: int):
        alerts = manager_fixture.get_alerts(
            start_timestamp=DEFAULT_TIMESTAMP,
            lowest_severity_filter=LOWEST_SEVERITY,
            limit=limit
        )
        assert isinstance(alerts, list)

        if len(alerts) <= 0:
            warnings.warn("There are no alerts in the system. TEST RESULTS MAY BE INACCURATE.")

        assert all(isinstance(alert, Alert) for alert in alerts)
        assert len(alerts) <= max(limit, DEFAULT_MAX_LIMIT)

    # Write tests to cover _paginate_results method of TrendMicroVisionOneManager using pytest. Do not use mocks, use real API calls.
    def test__paginate_results(self, manager_fixture: TrendMicroVisionOneManager):
        results = manager_fixture._paginate_results(
            method="GET",
            url=manager_fixture._get_full_url("get_alerts"),
            parser_method="build_alert_object",
            params={},
            limit=1
        )
        assert isinstance(results, list)

        if len(results) <= 0:
            warnings.warn("There are no alerts in the system. TEST RESULTS MAY BE INACCURATE.")
            return

        assert len(results) == 1
        assert all(isinstance(alert, Alert) for alert in results)

    # Write tests to cover _get_full_url method of TrendMicroVisionOneManager using pytest.
    def test__get_full_url(self, manager_fixture: TrendMicroVisionOneManager):
        full_url = manager_fixture._get_full_url("get_alerts")
        assert ENDPOINTS["get_alerts"] in full_url
        assert manager_fixture.api_root in full_url

    # Tests to cover search_endpoint, isolate_endpoint, unisolate_endpoint method of TrendMicroVisionOneManager using pytest. Do not use mocks, use real API calls.
    @pytest.mark.parametrize("ip", ["172.30.201.36", "172.30.201.83", "172.30.201.44"])
    def test_search_endpoint_by_ip(self, manager_fixture: TrendMicroVisionOneManager, ip: str):
        endpoint = manager_fixture.search_endpoint(ip=ip)
        assert endpoint
        assert ip in endpoint.ip_value

    @pytest.mark.parametrize("hostname", ["WINDOWS10", "tm-WINDOWS10-2", "WINDOWS10-clean"])
    def test_search_endpoint_by_hostname(self, manager_fixture: TrendMicroVisionOneManager, hostname: str):
        endpoint = manager_fixture.search_endpoint(hostname=hostname)
        assert endpoint
        assert endpoint.endpoint_name_value == hostname

    @pytest.mark.parametrize("ip", ["172.30.201.36", "172.30.201.83", "172.30.201.44"])
    def test_isolate_endpoint(self, manager_fixture: TrendMicroVisionOneManager, ip: str):
        endpoint = manager_fixture.search_endpoint(ip=ip)
        task_url = manager_fixture.isolate_endpoint(description=DEFAULT_DESCRIPTION, guid=endpoint.guid)

        assert task_url
        task = manager_fixture.get_task(task_url)

        while task.status == IN_PROGRESS_STATUS:
            task = manager_fixture.get_task(task_url)

        assert task.status in [SUCCESS_STATUS, FAILED_STATUS, REJECTED_STATUS]

    @pytest.mark.parametrize("ip", ["172.30.201.36", "172.30.201.83", "172.30.201.44"])
    def test_unisolate_endpoint(self, manager_fixture: TrendMicroVisionOneManager, ip: str):
        endpoint = manager_fixture.search_endpoint(ip=ip)
        task_url = manager_fixture.unisolate_endpoint(description=DEFAULT_DESCRIPTION, guid=endpoint.guid)

        assert task_url
        task = manager_fixture.get_task(task_url)

        while task.status == IN_PROGRESS_STATUS:
            task = manager_fixture.get_task(task_url)

        assert task.status in [SUCCESS_STATUS, FAILED_STATUS, REJECTED_STATUS]

    # Write tests to cover get_alert_by_id method of TrendMicroVisionOneManager using pytest. Do not use mocks, use real API calls.
    def test_get_alert_by_id(self, manager_fixture: TrendMicroVisionOneManager):
        alerts = manager_fixture.get_alerts(
            start_timestamp=DEFAULT_TIMESTAMP,
            lowest_severity_filter=LOWEST_SEVERITY,
            limit=DEFAULT_NUMBER_OF_ALERTS_FOR_TEST
        )
        assert isinstance(alerts, list)

        if len(alerts) <= 0:
            warnings.warn("There are alerts in the system. TEST RESULTS MAY BE INACCURATE.")

        for alert in alerts:
            alert_by_id = manager_fixture.get_alert_by_id(alert.alert_id)
            assert alert_by_id
            assert alert_by_id.alert_id == alert.alert_id

    @pytest.mark.parametrize("status", POSSIBLE_WORKBENCH_STATUSES)
    def test_update_alert(self, manager_fixture: TrendMicroVisionOneManager, status: str):
        alerts = manager_fixture.get_alerts(
            start_timestamp=DEFAULT_TIMESTAMP,
            lowest_severity_filter=LOWEST_SEVERITY,
            limit=DEFAULT_NUMBER_OF_ALERTS_FOR_TEST
        )
        assert isinstance(alerts, list)

        if len(alerts) <= 0:
            warnings.warn("There are alerts in the system. TEST RESULTS MAY BE INACCURATE.")

        for alert in alerts:
            for status in POSSIBLE_WORKBENCH_STATUSES:
                assert manager_fixture.update_alert(alert.alert_id, status)

    @pytest.mark.parametrize("script_name", TEST_SCRIPT_NAMES)
    def test_get_script_by_name(self, manager_fixture: TrendMicroVisionOneManager, script_name: str):
        script = manager_fixture.get_script_by_name(script_name)
        assert script
        assert script.raw_data["fileName"] == script_name

    @pytest.mark.parametrize("script_name", TEST_SCRIPT_NAMES)
    def test_run_script(self, manager_fixture: TrendMicroVisionOneManager, script_name: str):
        endpoint = manager_fixture.search_endpoint(ip="172.30.201.36")
        task_url = manager_fixture.run_script(
            script_name=script_name,
            script_parameters="string",
            guid=endpoint.guid
        )

        assert task_url
        task = manager_fixture.get_task(task_url)

        while task.status == IN_PROGRESS_STATUS:
            task = manager_fixture.get_task(task_url)

        assert task.status in [SUCCESS_STATUS, FAILED_STATUS, REJECTED_STATUS]
