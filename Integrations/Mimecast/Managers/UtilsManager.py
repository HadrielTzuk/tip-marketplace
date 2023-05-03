import requests
import datetime
from datetime import timezone
from constants import SEVERITIES
from MimecastExceptions import MimecastException
from SiemplifyUtils import convert_string_to_datetime
from constants import TIMEFRAME_MAPPING
from typing import Iterable, List, Any


def lazy_chunk_iterable(iterable_to_chunk: List[Any],
                        chunk_size: int,
                        ) -> Iterable[List[Any]]:
    for i in range(0, len(iterable_to_chunk), chunk_size):
        yield iterable_to_chunk[i:i+chunk_size]


def validate_response(response, error_msg=u'An error occurred'):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {unicode} Default message to display on error
    """

    try:
        response.raise_for_status()
    except requests.HTTPError as error:
        raise MimecastException(f'{error_msg}: {error} {error.response.content}')

    fail = response.json().get('fail', [])
    if fail:
        errors = fail[0].get('errors', []) if fail else []
        error_message = ", ".join([error.get('message', "") for error in errors])

        raise MimecastException(
            f"{error_msg}: {error_message or response.content}"
        )


def pass_severity_filter(siemplify, alert, lowest_severity, ingest_without_risk):
    # severity filter
    if lowest_severity:
        filtered_severities = SEVERITIES[SEVERITIES.index(lowest_severity.lower()):] if lowest_severity.lower() in \
                                                                                        SEVERITIES else []
        if not filtered_severities:
            siemplify.LOGGER.info(f'Risk is not checked. Invalid value provided for \"Lowest Risk To Fetch\" '
                                  f'parameter. Possible values are: Negligible, Low, Medium, High.')
        else:
            if alert.message_details.risk:
                if alert.message_details.risk.lower() not in filtered_severities:
                    siemplify.LOGGER.info(f'Message with risk: {alert.message_details.risk} did not pass filter. '
                                          f'Lowest risk to fetch is {lowest_severity}.')
                    return False
            else:
                if not ingest_without_risk:
                    siemplify.LOGGER.info(f'Message without risk did not pass filter. '
                                          f'\"Ingest Messages Without Risk\" parameter is unchecked.')
                    return False
    return True


def get_timestamps_from_range(range_string):
    """
    Get start and end time timestamps from range
    :param range_string: {str} Time range string
    :return: {tuple} start and end time timestamps
    """
    now = datetime.datetime.utcnow()
    today_datetime = datetime.datetime(year=now.year, month=now.month, day=now.day, hour=0, second=0)
    timeframe = TIMEFRAME_MAPPING.get(range_string)

    if isinstance(timeframe, dict):
        start_time, end_time = now - datetime.timedelta(**timeframe), now
    elif timeframe == TIMEFRAME_MAPPING.get("Last Week"):
        start_time, end_time = today_datetime + datetime.timedelta(-today_datetime.weekday(), weeks=-1), \
                               today_datetime + datetime.timedelta(-today_datetime.weekday())

    elif timeframe == TIMEFRAME_MAPPING.get("Last Month"):
        end_time = today_datetime.today().replace(day=1, hour=0, minute=0, second=0) - datetime.timedelta(days=1)
        start_time = today_datetime.today().replace(day=1, hour=0, minute=0, second=0) - datetime.timedelta(days=end_time.day)
        end_time = end_time + datetime.timedelta(days=1)
    else:
        return None, None

    return start_time, end_time


def get_timestamps(range_string, start_time_string, end_time_string):
    """
    Get start and end time timestamps
    :param range_string: {str} Time range string
    :param start_time_string: {str} Start time
    :param end_time_string: {str} End time
    :return: {tuple} start and end time timestamps
    """
    start_time, end_time = get_timestamps_from_range(range_string)

    if not start_time and start_time_string:
        start_time = convert_string_to_datetime(start_time_string)

    if not end_time and end_time_string:
        end_time = convert_string_to_datetime(end_time_string)

    if not start_time:
        raise Exception('\"Start Time\" should be provided, when \"Custom\" is selected in \"Time Frame\" parameter.')

    if not end_time:
        end_time = datetime.datetime.utcnow().replace(tzinfo=timezone.utc)

    if start_time > end_time:
        raise Exception("\"End Time\" should be later than \"Start Time\"")

    return start_time.isoformat(), end_time.isoformat()
