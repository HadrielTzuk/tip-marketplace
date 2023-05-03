import requests
import datetime
import re
import itertools

from SiemplifyUtils import utc_now, unix_now, convert_string_to_datetime, convert_timezone
from TIPCommon import (
    UNIX_FORMAT,
    DATETIME_FORMAT,
    read_ids,
    write_ids_with_timestamp,
    write_content,
    read_content
)
from constants import SEVERITIES, TIMEFRAME_MAPPING
from Microsoft365DefenderExceptions import (
    APIPermissionError,
    Microsoft365DefenderException,
    NotEnoughEntitiesException,
    TooManyRequestsError
)

EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"


def validate_response(response, error_msg=u'An error occurred'):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {unicode} Default message to display on error
    """
    try:
        if response.status_code == 429:
            raise TooManyRequestsError('Too many queries were executed. Rate limit is reached. '
                                       'Wait for a minute and try again.')
        response.raise_for_status()

    except requests.HTTPError as error:

        if response.status_code == 403:
            raise APIPermissionError(f'{error_msg}: {error} {error.response.content}')

        try:
            response.json()
        except Exception:
            raise Microsoft365DefenderException(f'{error_msg}: {error} {error.response.content}')

        api_error = response.json().get('error')
        error_message = response.json().get('error', {}).get('message') if isinstance(api_error, dict) else \
            response.json().get('error_description')

        raise Microsoft365DefenderException(
            f"{error_msg}: {error} {error_message or response.content}"
        )


# Move to TIPCommon
def validate_end_time(end_time, time_format=DATETIME_FORMAT):
    """
    Validate end time interval
    :param end_time: {datetime} Last run timestamp + 12 hours interval
    :param time_format: {int} The format of the output time. Ex DATETIME, UNIX
    :return: {datetime} if end_time > current_time, return current time, else return end_time
    """
    current_time = unix_now() if time_format == UNIX_FORMAT else utc_now()
    if end_time > current_time:
        return current_time
    else:
        return end_time


def pass_severity_filter(siemplify, alert, lowest_severity):
    # severity filter
    if lowest_severity:
        filtered_severities = SEVERITIES[SEVERITIES.index(lowest_severity.lower()):] if lowest_severity.lower() in \
                                                                                        SEVERITIES else []
        if not filtered_severities:
            siemplify.LOGGER.info(f'Severity is not checked. Invalid value provided for \"Lowest Severity To Fetch\" '
                                  f'parameter. Possible values are: Informational, Low, Medium, High.')
        if filtered_severities and alert.severity.lower() not in filtered_severities:
            siemplify.LOGGER.info(f'Incident with severity: {alert.severity} did not pass filter. Lowest severity to '
                                  f'fetch is {lowest_severity}.')
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
        start_time = convert_timezone(convert_string_to_datetime(start_time_string), "UTC")

    if not end_time and end_time_string:
        end_time = convert_timezone(convert_string_to_datetime(end_time_string), "UTC")

    if not start_time:
        raise Exception('\"Start Time\" should be provided, when \"Custom\" is selected in \"Time Frame\" parameter.')

    if not end_time:
        end_time = datetime.datetime.utcnow()

    return start_time.isoformat(), end_time.isoformat()


def convert_comma_separated_to_list(comma_separated):
    """
    Convert comma-separated string to list
    :param comma_separated: String with comma-separated values
    :return: List of values
    """
    return [item.strip() for item in comma_separated.split(',')] if comma_separated else []


def convert_list_to_comma_string(values_list):
    """
    Convert list to comma-separated string
    :param values_list: List of values
    :return: String with comma-separated values
    """
    return ', '.join(str(v) for v in values_list) if values_list and isinstance(values_list, list) else values_list


def check_if_key_provided(key, entities):
    """
    Checks whether the entity key for corresponding type is provided
    :param key: {str} Entity type key
    :param entities: {list} List of entity identifiers
    :return: True, exception otherwise
    """
    if key and not entities:
        raise NotEnoughEntitiesException(f"Action wasn't able to build the query, because not enough entity types were "
                                         f"supplied for the specified \".. Entity Keys\". Please disable \"Stop If Not "
                                         f"Enough Entities\" parameter or provide at least one entity for each "
                                         f"specified \".. Entity Key\".")
    return True


def get_email_address(entity):
    """
    get email address
    :param entity: {entity}
    :return: email address if found, else None.
    """
    try:
        if "Email" in entity.additional_properties:
            return entity.additional_properties["Email"]
        else:
            if re.match(EMAIL_REGEX, entity.identifier, re.IGNORECASE):
                return entity.identifier
    except:
        pass


def read_existing_incidents(siemplify):
    """
    Proxy to existing read_ids from TipCommon, handles after migration data structure changes to ids.json file
    :param siemplify: {ConnectorExecutionInstance}
    :return: dict with incidents / alerts data {incident_id_1: [alert_id_1, alert_id_2]}
    """
    existing_ids = read_ids(siemplify, default_value_to_return={})
    if isinstance(existing_ids, list):
        return {}
    return existing_ids


def write_existing_incidents(siemplify, existing_incidents, fetched_incidents, limit_of_incidents):
    """
    Proxy to existing write_ids_with_timestamp from TipCommon, handles after migration data structure changes to ids.json file
    :param siemplify: {ConnectorExecutionInstance}
    :param existing_incidents: {Dict} existing incidents from prev iteration
    :param fetched_incidents: {List[Incident]} fetched incidents on current cycle
    :param limit_of_incidents: {int} Limit of incidents to store
    :return: dict with incidents / alerts data {incident_id_1: [alert_id_1, alert_id_2]}
    """
    new_existing_incidents = {
        str(fetched_incident.incident_id):
            existing_incidents.get(str(fetched_incident.incident_id), []) +
            [alert.alert_id for alert in fetched_incident.alerts or []]
        for fetched_incident in fetched_incidents
    }
    existing_incidents = {key: value for key, value in existing_incidents.items() if key not in new_existing_incidents}

    if len(existing_incidents) + len(new_existing_incidents) > limit_of_incidents:
        # Ex: len(new_existing_incidents) -> 20, len(existing_incidents) -> 990, limit_of_incidents -> 1000
        # Start for slice -> 990 - (1000 - 20) = 10, Stop -> None
        start_index = len(existing_incidents) - (limit_of_incidents - len(new_existing_incidents))
        existing_incidents = dict(itertools.islice(
            existing_incidents.items(),
            start_index,
            None
        ))

    # Old 980 incidents + new 20 incidents -> 1000 incidents in total
    existing_incidents.update(new_existing_incidents)

    write_ids_with_timestamp(siemplify, existing_incidents)

def write_last_too_many_requests_occurrence(siemplify, encountered_at):
    """
    Save last occurrence of last TooManyRequests Error
    :param siemplify: {ConnectorExecutionInstance}
    :param encountered_at: {int} Encountered At in UNIX
    """
    if encountered_at is not None:
        siemplify.LOGGER.info(f"Writing last occurrence of TooManyRequests (429) error - "
                              f"{datetime.datetime.fromtimestamp(encountered_at/1000).isoformat()}")

    write_content(
        siemplify,
        content_to_write=encountered_at,
        file_name="toomanyrequests_last_occurrence.txt",
        db_key="toomanyrequests_last_occurrence",
    )


def read_last_too_many_requests_occurrence(siemplify):
    """
    Save last occurrence of last TooManyRequests Error
    :param siemplify: {ConnectorExecutionInstance}
    :param encountered_at: {int} Encountered At in UNIX
    """
    encountered_at = read_content(
        siemplify,
        file_name="toomanyrequests_last_occurrence.txt",
        db_key="toomanyrequests_last_occurrence",
    ) or None

    if encountered_at is not None:
        siemplify.LOGGER.info(f"Last occurrence of TooManyRequests (429) error - "
                              f"{datetime.datetime.fromtimestamp(encountered_at/1000).isoformat()}")

    return encountered_at
