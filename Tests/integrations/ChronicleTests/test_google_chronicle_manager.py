from __future__ import annotations

from typing import Iterable

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockFixture

from SiemplifyMarketPlace.Integrations.GoogleChronicle.Managers import exceptions
from SiemplifyMarketPlace.Integrations.GoogleChronicle.Managers.datamodels import ChronicleAlert, ChronicleCase
from SiemplifyMarketPlace.Integrations.GoogleChronicle.Managers.GoogleChronicleManager import GoogleChronicleManager
from SiemplifyMarketPlace.Tests.integrations.LoggerMock import Logger


FAILING_STR_VALUE = 'Not a valid value'
CASE_EXTERNAL_ID = 'dabef1d6-4a99-49e1-b54a-5c86cc04b363'
ALERT_TICKET_ID = 'de_52429075-03df-09a7-1ee8-c1a60778c075'
CASE_NEW_EXTERNAL_ID_FOR_MOST_NEW_CASES = '3a098933-dece-4e63-94fa-7d1a5e971a25'


def test_connectivity(chronicle_manager: GoogleChronicleManager) -> None:
    assert chronicle_manager.test_connectivity() is True


def test_no_connectivity(
        chronicle_manager: GoogleChronicleManager,
        mock_validate_response_to_raise_manager_error: MonkeyPatch
) -> None:
    with pytest.raises(exceptions.GoogleChronicleManagerError):
        chronicle_manager.test_connectivity()


def test_batch_update_cases_in_chronicle(chronicle_manager: GoogleChronicleManager, mocker: MockFixture) -> None:
    logger_error_spy = mocker.spy(Logger, 'error')

    cases_to_update = [
        ChronicleCase(
            id=1,
            status=0,
            priority=4,
            has_failed=False,
            external_id=2,
            tracking_time=123,
            stage='',
            display_name='Display Name 1',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            has_failed=True,
            external_id=3,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            external_id=None,
            raw_data={}
        ),
        ChronicleCase(
            external_id='None',
            raw_data={}
        ),
        ChronicleCase(
            external_id='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            has_failed=False,
            external_id=3,
            tracking_time=1234,
            stage='error',
            display_name='error',
            environment='error',
            raw_data={}
        ),
    ]

    updated_cases = chronicle_manager.batch_update_cases_in_chronicle(cases_to_update)

    assert isinstance(updated_cases, list)
    for i, (new_case, old_case) in enumerate(zip(updated_cases, cases_to_update)):
        assert isinstance(new_case, ChronicleCase)
        if i == 0:
            assert new_case.external_id == '84957e6d-450c-4813-999e-fc0409f11a2d'

        elif i == 1 or i == len(cases_to_update) - 1:
            assert new_case.external_id == CASE_NEW_EXTERNAL_ID_FOR_MOST_NEW_CASES

        elif 1 < i < len(cases_to_update) - 1:
            assert new_case.external_id == CASE_EXTERNAL_ID

        # elif i == len(cases_to_update) - 1:
        #     assert new_case.external_id == '3a098933-dece-4e63-94fa-7d1a5e971a25'

        assert new_case.has_failed is old_case.has_failed
        __assert_updated_cases_attributes(new_case, old_case)
        assert logger_error_spy.call_count == 0


def test_fail_batch_update_cases_in_chronicle(
        chronicle_manager: GoogleChronicleManager,
        mock_build_cases_batch_request_data_empty_str: MonkeyPatch,
) -> None:
    cases_to_update = [ChronicleCase(raw_data={})]

    with pytest.raises(
            exceptions.GoogleChronicleManagerError,
            match="Unable to update cases: 400 Client Error: Bad Request for url:",
    ):
        chronicle_manager.batch_update_cases_in_chronicle(cases_to_update)


def test_request_values_batch_update_cases_in_chronicle(
        chronicle_manager: GoogleChronicleManager,
        mocker: MockFixture,
) -> None:
    logger_error_spy = mocker.spy(Logger, 'error')

    cases_to_update = [
        ChronicleCase(
            id=None,
            status=1,
            priority=5,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=FAILING_STR_VALUE,
            status=1,
            priority=5,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=None,
            priority=5,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=None,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            has_failed=None,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            external_id=None,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            external_id=FAILING_STR_VALUE,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=None,
            stage='',
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=1234,
            stage=None,
            display_name='Display Name 2',
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=1234,
            stage='',
            display_name=None,
            environment='',
            raw_data={}
        ),
        ChronicleCase(
            id=2,
            status=1,
            priority=5,
            external_id=CASE_EXTERNAL_ID,
            tracking_time=1234,
            stage='',
            display_name='Display Name 2',
            environment=None,
            raw_data={}
        ),
    ]

    updated_cases = chronicle_manager.batch_update_cases_in_chronicle(cases_to_update)
    failing_none_value_attr = ()
    failing_str_value_attr = ()

    assert isinstance(updated_cases, list)
    for new_case, old_case in zip(updated_cases, cases_to_update):
        assert isinstance(new_case, ChronicleCase)
        assert new_case.has_failed is old_case.has_failed  # Never fails - maybe it's ok

        if old_case.id == FAILING_STR_VALUE:
            assert new_case.external_id == '19701000-aea9-4bea-bd98-7e7e8b20cd3a'

        elif old_case.id is None:
            assert new_case.external_id == CASE_EXTERNAL_ID

        else:
            assert new_case.external_id == CASE_NEW_EXTERNAL_ID_FOR_MOST_NEW_CASES

        __assert_updated_cases_attributes(new_case, old_case)

    assert logger_error_spy.call_count == len(
        (*failing_none_value_attr, *failing_str_value_attr)
    )


def test_error_response_batch_update_cases_in_chronicle(
        chronicle_manager: GoogleChronicleManager,
        mocker: MockFixture,
        mock_batch_update_cases_response_to_error: MonkeyPatch,
) -> None:
    logger_error_spy = mocker.spy(Logger, 'error')
    updated_cases = chronicle_manager.batch_update_cases_in_chronicle(
        [ChronicleCase(raw_data={})]
    )

    assert updated_cases[0].has_failed is True
    assert logger_error_spy.call_count == 1


def test_batch_update_alerts_in_chronicle(chronicle_manager: GoogleChronicleManager, mocker: MockFixture) -> None:
    logger_error_spy = mocker.spy(Logger, 'error')
    updated_cases = chronicle_manager.batch_update_cases_in_chronicle([ChronicleCase(raw_data={})])
    updated_case_id = updated_cases[0].external_id
    alerts_to_update = [
        ChronicleAlert(
            raw_data={},
            id='1',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default error Environment',
            comment='A comment about error',
            has_failed=False,
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='2',
            ticket_id=ALERT_TICKET_ID,
            creation_time=12345,
            environment='dsa',
            has_failed=True,
            tracking_time=54321,
            case_id=updated_case_id,
            group_id='5',
            usefulness=3
        ),
    ]

    updated_alerts = chronicle_manager.batch_update_alerts_in_chronicle(alerts_to_update)

    assert isinstance(updated_alerts, list)
    for i, (new_alert, old_alert) in enumerate(zip(updated_alerts, alerts_to_update)):
        assert isinstance(new_alert, ChronicleAlert)
        assert new_alert.has_failed is old_alert.has_failed

        __assert_updated_alerts_attributes(new_alert, old_alert)
        assert logger_error_spy.call_count == 0


def test_fail_batch_update_alerts_in_chronicle(
        chronicle_manager: GoogleChronicleManager,
        mock_build_alerts_batch_request_data_empty_str: MonkeyPatch,
) -> None:
    alerts_to_update = [ChronicleAlert(raw_data={})]

    with pytest.raises(
            exceptions.GoogleChronicleManagerError,
            match="Unable to update alerts: 400 Client Error: Bad Request for url:"
    ):
        chronicle_manager.batch_update_alerts_in_chronicle(alerts_to_update)


def test_request_values_and_error_response_batch_update_alerts_in_chronicle(
        chronicle_manager: GoogleChronicleManager,
        mocker: MockFixture,
) -> None:
    logger_error_spy = mocker.spy(Logger, 'error')
    updated_cases = chronicle_manager.batch_update_cases_in_chronicle(
        [ChronicleCase(raw_data={})]
    )
    updated_case_id = updated_cases[0].external_id
    alerts_to_update = [
        ChronicleAlert(
            raw_data={},
            id=None,
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id=FAILING_STR_VALUE,
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='1',
            ticket_id=None,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='1',
            ticket_id=FAILING_STR_VALUE,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='12',
            ticket_id=ALERT_TICKET_ID,
            creation_time=None,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='123',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=None,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='1234',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=None,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='12345',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment=None,
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='123456',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment=None,
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='1234567',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            has_failed=None,
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='12345678',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=None,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='123456789',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=None,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='1234567890',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause=None,
            case_id=updated_case_id,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='12345678901',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=None,
            group_id='7',
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='1234567890123',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=FAILING_STR_VALUE,
            group_id='7',
            usefulness=0
        ),
        ChronicleAlert(
            raw_data={},
            id='12356789012',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id=None,
            usefulness=1
        ),
        ChronicleAlert(
            raw_data={},
            id='1234567890123',
            ticket_id=ALERT_TICKET_ID,
            creation_time=1664785922,
            priority=4,
            status=0,
            environment='Default Environment',
            comment='A comment...',
            tracking_time=0,
            reason=1,
            root_cause='Just... \'cause',
            case_id=updated_case_id,
            group_id='7',
            usefulness=None
        ),
    ]
    updated_alerts = chronicle_manager.batch_update_alerts_in_chronicle(alerts_to_update)
    failing_none_value_attr = ('id', 'ticket_id')
    failing_str_value_attr = ('case_id', 'ticket_id')

    assert isinstance(updated_alerts, list)
    for new_alert, old_alert in zip(updated_alerts, alerts_to_update):
        assert isinstance(new_alert, ChronicleAlert)

        if __object_has_a_failing_none_attr(
                new_alert, failing_none_value_attr
        ) or __object_has_a_failing_str_attr(
            new_alert,
            failing_str_value_attr
        ):
            assert new_alert.has_failed is True, "Alert didn't fail"

        else:
            assert new_alert.has_failed is old_alert.has_failed, "Alert did fail"

        __assert_updated_alerts_attributes(new_alert, old_alert)

    assert logger_error_spy.call_count == len(
        (*failing_none_value_attr, *failing_str_value_attr)
    )


def __assert_updated_cases_attributes(new_case: ChronicleCase, old_case: ChronicleCase) -> None:
    assert new_case.raw_data == old_case.raw_data
    assert new_case.id == old_case.id
    assert new_case.priority == old_case.priority
    assert new_case.status == old_case.status
    assert new_case.environment == old_case.environment
    assert new_case.stage == old_case.stage
    assert new_case.tracking_time == old_case.tracking_time
    assert new_case.display_name == old_case.display_name


def __assert_updated_alerts_attributes(new_alert: ChronicleAlert, old_alert: ChronicleAlert) -> None:
    assert new_alert.raw_data == old_alert.raw_data
    assert new_alert.id == old_alert.id
    assert new_alert.ticket_id == old_alert.ticket_id
    assert new_alert.creation_time == old_alert.creation_time
    assert new_alert.priority == old_alert.priority
    assert new_alert.status == old_alert.status
    assert new_alert.environment == old_alert.environment
    assert new_alert.comment == old_alert.comment
    assert new_alert.tracking_time == old_alert.tracking_time
    assert new_alert.reason == old_alert.reason
    assert new_alert.root_cause == old_alert.root_cause
    assert new_alert.case_id == old_alert.case_id
    assert new_alert.group_id == old_alert.group_id
    assert new_alert.usefulness == old_alert.usefulness


def __object_has_a_failing_none_attr(obj: ChronicleCase | ChronicleAlert, attributes: Iterable[str]) -> bool:
    for attribute in attributes:
        if getattr(obj, attribute) is None:
            return True

    return False


def __object_has_a_failing_str_attr(obj: ChronicleCase | ChronicleAlert, attributes: Iterable[str]) -> bool:
    for attribute in attributes:
        if getattr(obj, attribute) == FAILING_STR_VALUE:
            return True

    return False
