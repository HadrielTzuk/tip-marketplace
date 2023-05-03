import os
import shutil
import re
from constants import DATETIME_FORMAT, UNIX_FORMAT
import json
import datetime
from SiemplifyUtils import utc_now, convert_datetime_to_unix_time, unix_now
from TIPCommon import validate_map_file
from EnvironmentCommon import EnvironmentHandle


STORED_IDS_LIMIT = 1000
TIMEOUT_THRESHOLD = 0.9
VALID_EMAIL_REGEXP = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


def is_valid_email(user_name):
    """
    Check if the user_name is valid email.
    :param user_name: {str} User name
    :return: {bool} True if valid email, else False
    """
    return bool(re.search(VALID_EMAIL_REGEXP, user_name))


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
        file.write(content.encode(encoding='UTF-8'))
        file.close()

    return local_path


def save_image_attachment(path, name, content):
    """
    Save image attachment to local path
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
        shutil.copyfileobj(content, file)

    return local_path


# Move to TIPCommon
def read_ids(siemplify, ids_file_name="ids.json"):
    """
    Read existing alerts IDs from ids file
    :param siemplify: {Siemplify} Siemplify object.
    :param ids_file_name: {str} The name of the ids file
    :return: {list} List of ids
    """
    ids_file_path = os.path.join(siemplify.run_folder, ids_file_name)

    if not os.path.exists(ids_file_path):
        return []

    try:
        with open(ids_file_path, "r") as f:
            return json.loads(f.read())
    except Exception as e:
        siemplify.LOGGER.error("Unable to read ids file: {}".format(e))
        siemplify.LOGGER.exception(e)
        return []


# Move to TIPCommon
def write_ids(siemplify, ids, ids_file_name="ids.json"):
    """
    Write ids to the ids file
    :param siemplify: {Siemplify} Siemplify object.
    :param ids: {list} The ids to write to the file
    :param ids_file_name: {str} The name of the ids file.
    :return: {bool}
    """
    ids = ids[-STORED_IDS_LIMIT:]

    try:
        ids_file_path = os.path.join(siemplify.run_folder, ids_file_name)

        if not os.path.exists(os.path.dirname(ids_file_path)):
            os.makedirs(os.path.dirname(ids_file_path))

        with open(ids_file_path, "w") as f:
            try:
                for chunk in json.JSONEncoder().iterencode(ids):
                    f.write(chunk)
            except:
                # Move seeker to start of the file
                f.seek(0)
                # Empty the content of the file (the partially written content that was written before the exception)
                f.truncate()
                # Write an empty dict to the events data file
                f.write("[]")
                raise

        siemplify.LOGGER.info("Write ids. Total ids = {}".format(len(ids)))
        return True

    except Exception as e:
        siemplify.LOGGER.error("Failed writing IDs to IDs file, ERROR: {0}".format(e.message))
        siemplify.LOGGER.exception(e)
        return False


# Move to TIPCommon
def get_last_success_time(siemplify, offset_with_metric, time_format=DATETIME_FORMAT, print_value=True):
    """
    Get last success time datetime
    :param siemplify: {siemplify} Siemplify object
    :param offset_with_metric: {dict} metric and value. Ex {'hours': 1}
    :param time_format: {int} The format of the output time. Ex DATETIME, UNIX
    :param print_value: {bool} Whether log the value or not
    :return: {time} If first run, return current time minus offset time, else return timestamp from file
    """
    last_run_timestamp = siemplify.fetch_timestamp(datetime_format=True)
    offset = datetime.timedelta(**offset_with_metric)
    current_time = utc_now()
    # Check if first run
    datetime_result = current_time - offset if current_time - last_run_timestamp > offset else last_run_timestamp
    unix_result = convert_datetime_to_unix_time(datetime_result)

    if print_value:
        siemplify.LOGGER.info("Last success time. Date time: {}. Unix: {}".format(datetime_result, unix_result))

    return unix_result if time_format == UNIX_FORMAT else datetime_result


def is_approaching_timeout(connector_starting_time, python_process_timeout):
    """
    Check if a timeout is approaching.
    :param connector_starting_time: {int} Connector start time
    :param python_process_timeout: {int} The python process timeout
    :return: {bool} True if timeout is close, False otherwise
    """
    processing_time_ms = unix_now() - connector_starting_time
    return processing_time_ms > python_process_timeout * 1000 * TIMEOUT_THRESHOLD


# Move to TIPCommon
def get_environment_common(siemplify, environment_field_name, environment_regex_pattern, map_file="map.json"):
    """
    Get environment common
    :param siemplify: {siemplify} Siemplify object
    :param environment_field_name: {str} The environment field name
    :param environment_regex_pattern: {str} The environment regex pattern
    :param map_file: {str} The map file
    :return: {EnvironmentHandle}
    """
    map_file_path = os.path.join(siemplify.run_folder, map_file)
    validate_map_file(siemplify, map_file_path)
    return EnvironmentHandle(map_file_path, siemplify.LOGGER, environment_field_name, environment_regex_pattern,
                             siemplify.context.connector_info.environment)


# Move to TIPCommon
def is_overflowed(siemplify, alert_info, is_test_run):
    """
    Check if overflowed
    :param siemplify: {Siemplify} Siemplify object.
    :param alert_info: {AlertInfo}
    :param is_test_run: {bool} Whether test run or not.
    :return: {bool}
    """
    try:
        return siemplify.is_overflowed_alert(
            environment=alert_info.environment,
            alert_identifier=alert_info.ticket_id,
            alert_name=alert_info.rule_generator,
            product=alert_info.device_product)

    except Exception as e:
        siemplify.LOGGER.error("Error validation connector overflow, ERROR: {}".format(e))
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    return False


# Move to TIPCommon
def save_timestamp(siemplify, alerts, timestamp_key="timestamp", incrementation_value=0, log_timestamp=True):
    """
    Save last timestamp for given alerts
    :param siemplify: {Siemplify} Siemplify object
    :param alerts: {list} The list of alerts to find the last timestamp
    :param timestamp_key: {str} key for getting timestamp from alert
    :param incrementation_value: {int} The value to increment last timestamp by milliseconds
    :param log_timestamp: {bool} Whether log timestamp or not
    :return: {bool} Is timestamp updated
    """
    if not alerts:
        siemplify.LOGGER.info("Timestamp is not updated since no alerts fetched")
        return False

    alerts = sorted(alerts, key=lambda alert: int(getattr(alert, timestamp_key)))
    last_timestamp = int(getattr(alerts[-1], timestamp_key)) + incrementation_value

    if log_timestamp:
        siemplify.LOGGER.info("Last timestamp is: {}".format(last_timestamp))

    siemplify.save_timestamp(new_timestamp=last_timestamp)
    return True


# Move to TIPCommon
def filter_old_alerts(logger, alerts, existing_ids, id_key="alert_id"):
    """
    Filter alerts that were already processed
    :param logger: {SiemplifyLogger} Siemplify logger
    :param alerts: {list} List of Alert objects
    :param existing_ids: {list} List of ids to filter
    :param id_key: {str} The key of identifier
    :return: {list} List of filtered Alert objects
    """
    filtered_alerts = []

    for alert in alerts:
        id = getattr(alert, id_key)

        if id not in existing_ids:
            filtered_alerts.append(alert)
        else:
            logger.info("The alert {} skipped since it has been fetched before".format(id))

    return filtered_alerts


def transform_html_content(content):
    """
    Replace reserved html characters with corresponding special characters
    :param content: {str} The content to transform
    :return: {str} Transformed content
    """
    return content.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


# Move to TIPCommon
def convert_list_to_comma_string(values_list):
    """
    Convert list to comma-separated string
    :param values_list: List of values
    :return: String with comma-separated values
    """
    return ', '.join(str(v) for v in values_list) if values_list and isinstance(values_list, list) else values_list


# Move to TIPCommon
def hours_to_milliseconds(hours):
    """
    Convert hours to milliseconds
    :param hours: {int} hours to convert
    :return: {int} converted milliseconds
    """
    return hours * 60 * 60 * 1000
