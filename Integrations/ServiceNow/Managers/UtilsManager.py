import datetime
import os

from SiemplifyUtils import utc_now
from constants import PRODUCT_NAME, GLOBAL_TIMEOUT_THRESHOLD_IN_MIN


def is_async_action_global_timeout_approaching(siemplify, start_time):
    return siemplify.execution_deadline_unix_time_ms - start_time < GLOBAL_TIMEOUT_THRESHOLD_IN_MIN * 60 * 1000


def separate_key_value_pairs_from_string(pairs_string):
    """
    Convert key:value paired string to dict
    ;:param pairs_string: {str} key:value paired comma separated string
    :return: {dict} {key: value} dict
    """
    custom_fields_dict = {}

    if pairs_string:
        for key_value in pairs_string.split(','):
            key, value = key_value.strip().split(':')
            custom_fields_dict[key.strip().lower()] = value.strip()

    return custom_fields_dict


def get_case_and_alerts_ids(case):
    """
    Extract incident case alerts ids
    :param case: cases object
    :return: {dict} Dict of {case id, [alert id]}
    """
    case_alert_ids = {}

    for alert in case.get('cyber_alerts', []):
        case_id, alert_id = case.get('identifier'), alert.get('identifier')
        if not alert_id:
            continue

        if not case_alert_ids.get(case_id):
            case_alert_ids[case_id] = []

        case_alert_ids[case_id].append(alert_id)

    return case_alert_ids


def get_incidents_numbers_from_case(case, prefix=None):
    """
    Extract incidents numbers from case
    :param case: case object
    :param prefix: number must starts with the prefix
    :return: {list} List of incidents numbers extracted from case
    """
    incidents_numbers_and_alert_ids = []

    for alert in case.get('cyber_alerts', []):
        incident_and_alert_ids = get_incident_number_from_alert(alert, prefix)
        if incident_and_alert_ids:
            incident_number, alert_id = incident_and_alert_ids
            incidents_numbers_and_alert_ids.append(incident_number)

    return incidents_numbers_and_alert_ids


def get_incident_number_from_alert(alert, prefix=None):
    """
    Extract incident number from alert
    :param alert: alert object
    :param prefix: number must starts with the prefix
    :return: {tuple} of incident number, alert id or None
    """
    alert_id = alert.get('identifier')

    if alert.get('reporting_product') == PRODUCT_NAME:
        incident_number = alert.get('additional_properties', {}).get('AlertName')
    else:
        incident_number = alert.get('additional_data')

    if not incident_number:
        return None

    if prefix:
        if incident_number.startswith(prefix):
            return incident_number, alert_id
    else:
        return incident_number, alert_id


def validate_timestamp(last_run_timestamp, offset_in_hours=None):
    """
    Validate timestamp in range
    :param last_run_timestamp: {datetime} last run timestamp
    :param offset_in_hours: {int} backward hours
    :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
    """
    current_time = utc_now()
    # Check if first run
    if not offset_in_hours:
        timedelta = datetime.timedelta()
    else:
        timedelta = datetime.timedelta(hours=offset_in_hours)
    if current_time - last_run_timestamp > timedelta:
        return current_time - timedelta
    else:
        return last_run_timestamp


def save_attachment(path, name, content):
    """
    Save attachment to local path
    :param path: {str} Path of the folder, where files should be saved
    :param name: {str} File name to be saved
    :param content: {str} File content
    :return: {str} Path to the downloaded files
    """
    # Create path if not exists
    if not os.path.exists(path):
        os.makedirs(path)
    # File local path
    local_path = os.path.join(path, name)
    with open(local_path, 'wb') as file:
        file.write(content)
        file.close()

    return local_path
