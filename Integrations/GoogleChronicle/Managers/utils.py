import os
import datetime
import arrow
import json
import requests
import hashlib
from SiemplifyUtils import (
    utc_now,
    convert_datetime_to_unix_time,
    unix_now,
    convert_string_to_datetime,
    convert_unixtime_to_datetime,
    convert_string_to_unix_time
)
from EnvironmentCommonOld import EnvironmentHandle
from exceptions import InvalidTimeException
import exceptions
import consts
from dateutil.relativedelta import relativedelta
import copy
import operator
from TIPCommon import read_content, write_content, is_empty_string_or_none
import re


# Move to TIPCommon
UNIX_FORMAT = 1
DATETIME_FORMAT = 2
VALID_EMAIL_REGEXP = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
TIMESTAMP_KEY = "timestamp"
NUM_OF_MILLI_IN_SEC = 1000


OPERATOR_FUNCTIONS = {
    "=": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    "<": operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
}


def datetime_to_rfc3339(datetime_obj: datetime.datetime) -> str:
    """
    Convert datetime object to RFC 3999 representation
    :param datetime_obj: {datetime.datetime} The datetime object to convert
    :return: {str} The RFC 3999 representation of the datetime
    """
    return datetime_obj.strftime(consts.TIME_FORMAT)


# Move to TIPCommon
def get_last_success_time(siemplify, offset_with_metric, time_format=DATETIME_FORMAT, print_value=True,
                          timestamp_file_name=None, timestamp_db_key=None):
    """
    Get last success time datetime
    :param siemplify: {siemplify} Siemplify object
    :param offset_with_metric: {dict} metric and value. Ex {'hours': 1}
    :param time_format: {int} The format of the output time. Ex DATETIME, UNIX
    :param print_value: {bool} Whether log the value or not
    :param timestamp_file_name: {str} The name of the timestamp file
    :param timestamp_db_key: {str} The key to use for timestamp file
    :return: {time} If first run, return current time minus offset time, else return timestamp from file
    """
    last_run_timestamp = fetch_timestamp_by_timestamp_file(
        siemplify, timestamp_file_name, timestamp_db_key, datetime_format=True
    ) if timestamp_file_name else siemplify.fetch_timestamp(datetime_format=True)

    offset = datetime.timedelta(**offset_with_metric)
    current_time = utc_now()
    # Check if first run
    datetime_result = current_time - offset if current_time - last_run_timestamp > offset else last_run_timestamp
    unix_result = convert_datetime_to_unix_time(datetime_result)
    if print_value:
        siemplify.LOGGER.info('Last success time. Date time:{}. Unix:{}'.format(datetime_result, unix_result))
    return unix_result if time_format == UNIX_FORMAT else datetime_result


def validate_response(response, error_msg='An error occurred'):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {unicode} Default message to display on error
    """
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        raise Exception(
            '{error_msg}: {error} {text}'.format(
                error_msg=error_msg,
                error=error,
                text=error.response.content)
        )

    return True


# Move to TIPCommon
def get_environment_common(siemplify, environment_field_name, environment_regex_pattern, map_file=u'map.json'):
    """
    Get environment common
    :param siemplify: {siemplify} Siemplify object
    :param environment_field_name: {string} The environment field name
    :param environment_regex_pattern: {string} The environment regex pattern
    :param map_file: {string} The map file
    :return: {EnvironmentHandle}
    """
    map_file_path = os.path.join(siemplify.run_folder, map_file)
    validate_map_file(siemplify, map_file_path)
    return EnvironmentHandle(map_file_path, siemplify.LOGGER, environment_field_name, environment_regex_pattern,
                             siemplify.context.connector_info.environment)


# Move to TIPCommon
def validate_map_file(siemplify, map_file_path):
    """
    Validate if map file is already exist, otherwise create it.
    @param siemplify: Siemplify object to log
    @param map_file_path: Map file path
    """
    try:
        if not os.path.exists(map_file_path):
            with open(map_file_path, 'w+') as map_file:
                map_file.write(json.dumps(
                    {
                        "Original environment name": "Desired environment name",
                        "Env1": u"MyEnv1"
                    })
                )
                siemplify.LOGGER.info("Mapping file was created at {}".format(map_file))
    except Exception as e:
        siemplify.LOGGER.error("Unable to create mapping file: {}".format(e))
        siemplify.LOGGER.exception(e)


# Move to TIPCommon
def filter_old_alerts(logger, alerts, existing_ids, id_key='alert_id'):
    """
    Filter alerts that were already processed
    :param logger: {SiemplifyLogger} Siemplify logger
    :param alerts: {list} The alerts to filter
    :param existing_ids: {list} The ids to filter
    :param id_key: {unicode} The key of identifier
    :return: {list} The filtered alerts
    """
    filtered_alerts = []
    for alert in alerts:
        id = getattr(alert, id_key)
        if id not in existing_ids:
            filtered_alerts.append(alert)
        else:
            logger.info(
                'The alert {} skipped since it has been fetched before'.format(id)
            )

    return filtered_alerts


# Move to TIPCommon
def read_ids(siemplify, ids_file_name='ids.json', max_hours_backwards=24):
    """
    Read existing (already seen) alert ids from the ids.json file
    :param max_hours_backwards: {int} Max amount of hours to keep ids in the file (to prevent it from getting too big)
    :param ids_file_name: {str} The name of the ids file
    :return:{dict} A dict describing the already seen ids {id: the unixtime when it was first seen}
    """
    ids_file_path = os.path.join(siemplify.run_folder, ids_file_name)
    siemplify.LOGGER.info("Fetching existing IDs from: {0}".format(ids_file_path))

    try:
        if not os.path.exists(ids_file_path):
            siemplify.LOGGER.info("Ids file doesn't exist at path {}".format(ids_file_path))
            return {}

        with open(ids_file_path, 'r') as f:
            siemplify.LOGGER.info("Reading existing ids from ids file")
            existing_ids = json.loads(f.read())

            filtered_ids = {}
            # Insert IDs that did not passed time retention time limit.
            for alert_id, timestamp in existing_ids.items():
                if timestamp > arrow.utcnow().shift(hours=-max_hours_backwards).timestamp * 1000:
                    filtered_ids[alert_id] = timestamp

            return filtered_ids

    except Exception as e:
        siemplify.LOGGER.error("Unable to read ids file: {}".format(e))
        siemplify.LOGGER.exception(e)
        return {}


# Move to TIPCommon
def write_ids(siemplify, ids, ids_file_name='ids.json'):
    """
    Write ids to the ids file
    :param ids_file_name: {str} The name of the ids file
    :param ids: {dict} The ids to write to the file
    """
    try:
        ids_file_path = os.path.join(siemplify.run_folder, ids_file_name)
        siemplify.LOGGER.info("Writing ids to file: {}".format(ids_file_path))

        if not os.path.exists(os.path.dirname(ids_file_path)):
            siemplify.LOGGER.info("Ids file doesn't exist at {}. Creating new file.".format(ids_file_path))
            os.makedirs(os.path.dirname(ids_file_path))

        with open(ids_file_path, 'w') as f:
            try:
                for chunk in json.JSONEncoder().iterencode(ids):
                    f.write(chunk)
            except:
                # Move seeker to start of the file
                f.seek(0)
                # Empty the content of the file (the partially written content that was written before the exception)
                f.truncate()
                # Write an empty dict to the events data file
                f.write("{}")
                raise

    except Exception as e:
        siemplify.LOGGER.error("Failed writing IDs to IDs file, ERROR: {0}".format(e))
        siemplify.LOGGER.exception(e)


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

    except Exception as err:
        siemplify.LOGGER.error(
            'Error validation connector overflow, ERROR: {}'.format(err))
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    return False


# Move to TIPCommon
def save_timestamp(siemplify, alerts, timestamp_key='timestamp', incrementation_value=0, log_timestamp=True):
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
        siemplify.LOGGER.info('Timestamp is not updated since no alerts fetched')
        return False
    alerts = sorted(alerts, key=lambda alert: int(getattr(alert, timestamp_key)))
    last_timestamp = int(getattr(alerts[-1], timestamp_key)) + incrementation_value

    if log_timestamp:
        siemplify.LOGGER.info('Saving timestamp:{}'.format(last_timestamp))

    siemplify.save_timestamp(new_timestamp=last_timestamp)
    return True


# Move to TIPCommon
def is_approaching_timeout(python_process_timeout, connector_starting_time, timeout_threshold=0.9):
    """
    Check if a timeout is approaching.
    :param python_process_timeout: {int} The python process timeout
    :return: {bool} True if timeout is close, False otherwise
    """
    processing_time_ms = unix_now() - connector_starting_time
    return processing_time_ms > python_process_timeout * 1000 * timeout_threshold


def get_hash_type(file_hash: str) -> str:
    """
    Get the type of a hash by its length
    :param file_hash: {str} The hash
    :return: {str} The type of the hash
    """
    if len(file_hash) == 32:
        return consts.HashArtifactTypes.MD5
    elif len(file_hash) == 64:
        return consts.HashArtifactTypes.SHA256
    elif len(file_hash) == 40:
        return consts.HashArtifactTypes.SHA1

    raise exceptions.GoogleChronicleValidationError("Invalid hash type. Supported types: MD5, SHA1, SHA256.")


def get_timestamps_from_range(range_string, alert_start_time=None, alert_end_time=None):
    """
    Get start and end time timestamps from range
    :param range_string: {str} Time range string
    :param alert_start_time: {str} Start time of the alert
    :param alert_end_time: {str} End time of the alert
    :return: {tuple} start and end time timestamps
    """
    now = datetime.datetime.utcnow()
    timeframe = consts.TIMEFRAME_MAPPING.get(range_string)

    if isinstance(timeframe, dict):
        start_time, end_time = now - datetime.timedelta(**timeframe), now
    elif timeframe == consts.TIMEFRAME_MAPPING.get("Last Week"):
        start_time, end_time = now - datetime.timedelta(weeks=1), now
    elif timeframe == consts.TIMEFRAME_MAPPING.get("Last Month"):
        start_time, end_time = now - relativedelta(months=1), now
    elif timeframe == consts.TIMEFRAME_MAPPING.get("Alert Time Till Now"):
        start_time, end_time = alert_start_time, now
    elif timeframe == consts.TIMEFRAME_MAPPING.get("5 Minutes Around Alert Time"):
        start_time, end_time = alert_start_time - datetime.timedelta(minutes=5), \
                               alert_end_time + datetime.timedelta(minutes=5)
    elif timeframe == consts.TIMEFRAME_MAPPING.get("30 Minutes Around Alert Time"):
        start_time, end_time = alert_start_time - datetime.timedelta(minutes=30), \
                               alert_end_time + datetime.timedelta(minutes=30)
    elif timeframe == consts.TIMEFRAME_MAPPING.get("1 Hour Around Alert Time"):
        start_time, end_time = alert_start_time - datetime.timedelta(hours=1), \
                               alert_end_time + datetime.timedelta(hours=1)
    else:
        return None, None

    return datetime_to_rfc3339(start_time), datetime_to_rfc3339(end_time)


def get_timestamps(range_string, start_time_string=None, end_time_string=None, alert_start_time=None, alert_end_time=None):
    """
    Get start and end time timestamps
    :param range_string: {str} Time range string
    :param start_time_string: {str} Start time
    :param end_time_string: {str} End time
    :param alert_start_time: {str} Start time of the alert
    :param alert_end_time: {str} End time of the alert
    :return: {tuple} start and end time timestamps
    """
    start_time, end_time = get_timestamps_from_range(range_string, alert_start_time, alert_end_time)
    current_time_rfc3339 = datetime_to_rfc3339(datetime.datetime.utcnow())

    if not start_time and start_time_string:
        start_time = datetime_to_rfc3339(convert_string_to_datetime(start_time_string))

    if not end_time and end_time_string:
        if end_time_string.lower() == consts.NOW:
            end_time = current_time_rfc3339
        else:
            end_time = datetime_to_rfc3339(convert_string_to_datetime(end_time_string))

    if not start_time:
        raise InvalidTimeException(
            "\"Start Time\" should be provided, when \"Custom\" is selected "
            "in \"Time Frame\" parameter.")

    if not end_time or end_time > current_time_rfc3339:
        end_time = current_time_rfc3339

    if start_time > end_time:
        raise Exception("\"End Time\" should be later than \"Start Time\"")

    return start_time, end_time


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


def is_valid_email(user_name):
    """
    Check if the user_name is valid email.
    :param user_name: {str} User name
    :return: {bool} True if valid email, else False
    """
    return bool(re.search(VALID_EMAIL_REGEXP, user_name))


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


def get_domain_from_entity(identifier):
    """
    Extract domain from entity identifier
    :param identifier: {str} the identifier of the entity
    :return: {str} domain part from entity identifier
    """
    if "@" in identifier:
        return identifier.split("@", 1)[-1]
    try:
        import tldextract
        result = tldextract.extract(identifier)
        join_with = '.'
        result_to_join = [item for item in [result.subdomain, result.domain, result.suffix] if item]
        return join_with.join(result_to_join)

    except ImportError:
        raise ImportError("tldextract is not installed. Use pip and install it.")


def save_timestamp_by_timestamp_file(siemplify, alerts, timestamp_key='timestamp', incrementation_value=0,
                                     log_timestamp=True, timestamp_file_name="timestamp.stmp",
                                     timestamp_db_key="timestamp"):
    """
    Save last timestamp for given alerts
    :param siemplify: {Siemplify} Siemplify object
    :param alerts: {list} The list of alerts to find the last timestamp
    :param timestamp_key: {str} key for getting timestamp from alert
    :param incrementation_value: {int} The value to increment last timestamp by milliseconds
    :param log_timestamp: {bool} Whether log timestamp or not
    :param timestamp_file_name: {str} The name of the timestamp file
    :param timestamp_db_key: {str} The key to use for timestamp file
    :return: {bool} Is timestamp updated
    """
    if not alerts:
        siemplify.LOGGER.info("Timestamp is not updated since no alerts fetched")
        return False

    alerts = sorted(alerts, key=lambda alert: int(getattr(alert, timestamp_key)))
    last_timestamp = int(getattr(alerts[-1], timestamp_key)) + incrementation_value

    try:
        write_content(siemplify, str(last_timestamp), file_name=timestamp_file_name, db_key=timestamp_db_key)

        if log_timestamp:
            siemplify.LOGGER.info("Saving timestamp:{}".format(last_timestamp))

        return True

    except Exception as e:
        siemplify.LOGGER.error(f"Failed writing timestamp to {timestamp_file_name} file, ERROR: {e}")
        siemplify.LOGGER.exception(e)
        return False


def fetch_timestamp_by_timestamp_file(siemplify, timestamp_file_name="timestamp.stmp", timestamp_db_key="timestamp",
                                      datetime_format=True):
    """
    Fetch timestamp from timestamp file
    :param siemplify: {Siemplify} Siemplify object
    :param timestamp_file_name: {str} The name of the timestamp file
    :param timestamp_db_key: {str} The key to use for timestamp file
    :param datetime_format: {bool} Specifies if datetime format should be returned
    return: {timestamp}
    """
    try:
        last_run_time = read_content(siemplify, file_name=timestamp_file_name, db_key=timestamp_db_key,
                                     default_value_to_return=0)
    except Exception:
        siemplify.LOGGER.error(f"Unable to read timestamp file")
        last_run_time = 0

    return convert_unixtime_to_datetime(int(last_run_time)) if datetime_format else int(last_run_time)


def generate_hash(string):
    """
    Generate the SHA1 hash from string
    :param string: {str} string to use in hash
    return: {str} generated hash
    """
    hash_obj = hashlib.sha1(string.encode())
    return hash_obj.hexdigest()


def get_formatted_date_from_timestamp(timestamp):
    """
    Format timestamp to date string with specific format
    :param timestamp: {int} timestamp to format
    :return: {str} formatted date string
    """
    return "{}Z".format(datetime.datetime.fromtimestamp(timestamp / 1000, tz=datetime.timezone.utc)
                        .strftime(consts.UNIFIED_CONNECTOR_DATETIME_FORMAT)[:-3])


def separate_data_per_multiple_values_keys(raw_data, keys, additional_info):
    """
    Separate data per keys that contain multiple values
    :param raw_data: {dict} raw data
    :param keys: {list} list of keys with multiple values
    :param additional_info: {dict} additional info that separated items should contain
    :return: {list} list of separated data items
    """
    initial_data = copy.deepcopy(raw_data)
    initial_data.update(additional_info)
    key_values = {}

    for key in keys:
        values = next(get_value_from_nested_dict(raw_data, key.split(consts.NESTED_KEYS_DELIMITER)))

        if values:
            key_values[key] = values

    items_count = max([len(values) for values in key_values.values()]) if key_values else 0
    items = [] if items_count else [initial_data]

    for i in range(items_count):
        initial_data = copy.deepcopy(initial_data)

        for key, value in key_values.items():
            initial_data[key.replace(consts.NESTED_KEYS_DELIMITER, "_")] = get_list_item_by_index(value, i)

        items.append(initial_data)

    return items


def get_value_from_nested_dict(raw_data, keys_list):
    """
    Get value from nested dict with list of keys
    :param raw_data: {dict} raw data
    :param keys_list: {list} list of keys
    :return: extracted value
    """
    for key in keys_list:
        if isinstance(raw_data.get(key), dict):
            keys_list.pop(0)
            yield from get_value_from_nested_dict(raw_data.get(key), keys_list)
        elif isinstance(raw_data.get(key), list) and len(keys_list) > 1:
            keys_list.pop(0)
            merged_dict = dict()

            for list_item in raw_data.get(key):
                if not isinstance(list_item, dict):
                    continue

                for list_item_key, list_item_value in list_item.items():
                    if list_item_key in merged_dict:
                        merged_dict[list_item_key] += list_item_value
                    else:
                        merged_dict[list_item_key] = list_item_value

                    unique_values = []
                    for item in merged_dict.get(list_item_key, []):
                        if item not in unique_values:
                            unique_values.append(item)
                    merged_dict[list_item_key] = unique_values

            yield from get_value_from_nested_dict(merged_dict, keys_list)
        else:
            yield raw_data.get(key)


def get_list_item_by_index(data, index):
    """
    Get list item by index
    :param data: {list} the list
    :param index: {int} the index
    :return: the list item
    """
    try:
        return data[index]
    except IndexError:
        return None


def get_filters_by_alert_type(logger, dynamic_filters, alert_type):
    """
    Get alert type filters from dynamic filters list
    :param logger: Siemplify logger
    :param dynamic_filters: {list} list of dynamic filters
    :param alert_type: {str} alert type
    :return: {list} the list of filters
    """
    filters = []
    supported_filters = consts.ALERT_TYPES_SUPPORTED_FILTERS.get(alert_type)

    for dynamic_filter in dynamic_filters:
        if len(dynamic_filter.split(consts.FILTER_TYPE_DELIMITER)) < 2:
            logger.warn(f"Invalid filter provided in the dynamic list \"{dynamic_filter}\". Ignoring this filter.")
            continue

        alert_type_key, alert_type_filter = dynamic_filter.split(consts.FILTER_TYPE_DELIMITER)

        if alert_type_key.lower() not in consts.ALERT_TYPES_SUPPORTED_FILTERS.keys():
            logger.warn(f"Invalid alert type provided in the dynamic list filter \"{alert_type_key}\". Ignoring "
                        f"this filter.")
            continue

        if alert_type_key.lower() != alert_type:
            continue

        filter_key, filter_operator, filter_values = "", "", ""

        for supported_operator in consts.SUPPORTED_OPERATORS:
            items = [item.strip() for item in alert_type_filter.split(supported_operator) if item.strip()]

            if len(items) == 2:
                filter_key = items[0]
                filter_operator = supported_operator
                filter_values = [value.strip().lower() for value in items[1].split(consts.FILTER_VALUES_DELIMITER)
                                 if value.strip()]
                break

        if not (filter_key and filter_operator and filter_values):
            logger.warn(f"Invalid filter provided in the dynamic list \"{dynamic_filter}\". Ignoring this filter.")
            continue

        if filter_key not in supported_filters.keys():
            logger.warn(f"Invalid filter key provided in the dynamic list \"{dynamic_filter}\". Ignoring this filter.")
            continue

        if filter_operator not in supported_filters.get(filter_key).get("operators", []):
            logger.warn(f"Invalid filter operator provided in the dynamic list \"{dynamic_filter}\". Supported "
                        f"operators: {','.join(supported_filters.get(filter_key).get('operators', []))}. "
                        f"Ignoring this filter.")
            continue

        if supported_filters.get(filter_key).get("possible_values", []) and \
                list(set(filter_values) - set(supported_filters.get(filter_key).get("possible_values", []))):
            logger.warn(f"Invalid values provided in the dynamic list \"{dynamic_filter}\". Supported values: "
                        f"{','.join(supported_filters.get(filter_key).get('possible_values', []))}. "
                        f"Ignoring this filter.")
            continue

        if len(filter_values) > 1 and filter_operator not in consts.MULTIPLE_VALUES_SUPPORTED_OPERATORS.keys():
            logger.warn(f"Invalid filter operator provided in the dynamic list for \"{dynamic_filter}\" with multiple"
                        f" values. Supported operators: "
                        f"{','.join(consts.MULTIPLE_VALUES_SUPPORTED_OPERATORS.keys())}. Ignoring this filter.")
            continue

        filters.append({
            "filter_key": filter_key,
            "operator": filter_operator,
            "filter_values": prepare_filter_values(supported_filters, filter_key, filter_values),
            "response_key": supported_filters.get(filter_key).get("response_key")
        })

    return filters


def prepare_filter_values(supported_filters, filter_key, filter_values):
    """
    Prepare filter values by applying mapping and transformer functions
    :param supported_filters: {list} List of supported filters
    :param filter_key: {str} filter key
    :param filter_values: {list} list of filter values
    :return: {list} list of transformed filter values
    """
    values = []

    for filter_value in filter_values:
        value = filter_value

        if supported_filters.get(filter_key).get("values_mapping"):
            value = supported_filters.get(filter_key).get("values_mapping").get(filter_value)

        if supported_filters.get(filter_key).get("transformer"):
            value = supported_filters.get(filter_key).get("transformer")(value)

        values.append(value)

    return values


def pass_filters(logger, alert, filters):
    """
    Check if alert passes all filters
    :param logger: Siemplify logger
    :param alert: alert object depends on alert type
    :param filters: {list} list of filter items dicts
    :return: {bool} True if alert passes all filters, False otherwise
    """
    for filter_item in filters:
        filter_results = []

        for filter_value in filter_item.get("filter_values"):
            response_value = getattr(alert, filter_item.get("response_key"))
            response_value = response_value.lower() if isinstance(response_value, str) else response_value

            filter_results.append(
                response_value is not None
                and OPERATOR_FUNCTIONS.get(filter_item.get("operator"))(response_value, filter_value)
            )

        if filter_item.get("operator") in consts.MULTIPLE_VALUES_SUPPORTED_OPERATORS.keys():
            if consts.MULTIPLE_VALUES_SUPPORTED_OPERATORS.get(filter_item.get("operator")) \
                    == consts.FILTER_LOGIC.get("or") \
                    and not next((filter_result for filter_result in filter_results if filter_result), None):
                logger.info(f"'{alert.id}' did not pass filters.")
                return False
            elif consts.MULTIPLE_VALUES_SUPPORTED_OPERATORS.get(filter_item.get("operator")) \
                    == consts.FILTER_LOGIC.get("and") and not all(filter_results):
                logger.info(f"'{alert.id}' did not pass filters.")
                return False
        elif not all(filter_results):
            logger.info(f"'{alert.id}' did not pass filters.")
            return False

    return True


def convert_hours_to_milliseconds(hours):
    """
    Convert hours to milliseconds
    :param hours: {int} hours to convert
    :return: {int} converted milliseconds
    """
    return hours * 60 * 60 * 1000


def rename_dict_key(original_dict, original_key, new_key):
    """
    Rename key in dict
    :param original_dict: {dict} dict to transform
    :param original_key: {str} original key
    :param new_key: {str} new key
    :return: {dict} transformed dict
    """
    original_dict = copy.deepcopy(original_dict)
    original_dict[new_key] = original_dict.pop(original_key)
    return original_dict


def fix_key_value_pair(raw_event):
    """
    Fix key/value pairs in dict
    :param raw_event: {dict} raw data
    :return: {dict} transformed dict
    """
    all_keys = {key: value for key, value in raw_event.items() if key.count('_key') > 0}

    for key, key_value in all_keys.items():
        value_key = key.replace('_key', '_value')
        value = raw_event.get(value_key)
        if value is not None:
            raw_event[key.replace('_key', f"_{key_value}")] = value

    return raw_event


def get_prefix_from_string(string, separator=consts.STRING_PREFIX_SEPARATOR):
    """
    Get prefix from string
    :param string: {str} string
    :param separator: {str} separator to use for string splitting
    :return: {str} prefix
    """
    return string.split(separator)[0]


def get_last_success_time_for_job(siemplify, offset_with_metric, time_format=DATETIME_FORMAT, print_value=True,
                                  microtime=False, timestamp_key=TIMESTAMP_KEY):

    last_run_timestamp = fetch_timestamp_for_job(siemplify, timestamp_key, datetime_format=True)
    offset = datetime.timedelta(**offset_with_metric)
    current_time = utc_now()
    # Check if first run
    datetime_result = current_time - offset if current_time - last_run_timestamp > offset else last_run_timestamp
    unix_result = convert_datetime_to_unix_time(datetime_result)
    unix_result = unix_result if not microtime else int(unix_result / NUM_OF_MILLI_IN_SEC)

    if print_value:
        siemplify.LOGGER.info('Last success time. Date time:{}. Unix:{}'.format(datetime_result, unix_result))
    return unix_result if time_format == UNIX_FORMAT else datetime_result


def save_timestamp_for_job(siemplify, new_timestamp=unix_now(), timestamp_key=TIMESTAMP_KEY):
    if isinstance(new_timestamp, datetime.datetime):
        new_timestamp = convert_datetime_to_unix_time(new_timestamp)

    try:
        siemplify.set_scoped_job_context_property(property_key=timestamp_key, property_value=json.dumps(new_timestamp))
    except Exception as e:
        raise Exception("Failed saving timestamps to db, ERROR: {0}".format(e))


def fetch_timestamp_for_job(siemplify, timestamp_key=TIMESTAMP_KEY, datetime_format=False):
    try:
        last_run_time = siemplify.get_scoped_job_context_property(property_key=timestamp_key)
    except Exception as e:
        raise Exception("Failed reading timestamps from db, ERROR: {0}".format(e))

    if last_run_time is None:
        last_run_time = 0
    try:
        last_run_time = int(last_run_time)
    except:
        last_run_time = convert_string_to_unix_time(last_run_time)

    if datetime_format:
        last_run_time = convert_unixtime_to_datetime(last_run_time)
    else:
        last_run_time = int(last_run_time)

    return last_run_time


def read_ids_for_job(siemplify, db_key, default_value_to_return=None):
    try:
        str_data = siemplify.get_scoped_job_context_property(property_key=db_key)

        # Check if the db key exists
        if is_empty_string_or_none(str_data):

            siemplify.LOGGER.info('Key: "{}" does not exist in the database. Returning default value instead: '
                                  '{}'.format(db_key, default_value_to_return))
            return default_value_to_return

        data = json.loads(str_data)
        return data

    # If an error happened in the json.loads methods
    except TypeError as err:
        siemplify.LOGGER.error(
            'Failed to parse data as JSON. Returning default value instead: "{0}". \nERROR: {1}'.format(
                default_value_to_return, err)
        )
        siemplify.LOGGER.exception(err)
        return default_value_to_return

    # If there is a connection problem with the DB
    except Exception as error:
        siemplify.LOGGER.error("Exception was raised from the database.  ERROR: {}.".format(error))
        siemplify.LOGGER.exception(error)
        raise


def write_ids_for_job(siemplify, content_to_write, db_key, default_value_to_set=None):
    content_to_write = content_to_write[-consts.MAX_FETCH_LIMIT_FOR_JOB:]
    try:
        str_data = json.dumps(content_to_write, separators=(',', ':'))
        siemplify.set_scoped_job_context_property(property_key=db_key, property_value=str_data)

    # If an error happened in the json.dumps methods
    except TypeError as err:
        siemplify.LOGGER.error(
            'Failed parsing JSON to string. Writing default value instead: "{}". \nERROR: {}'.format(
                default_value_to_set, err)
        )
        siemplify.LOGGER.exception(err)
        siemplify.set_scoped_job_context_property(
            property_key=db_key,
            property_value=json.dumps(default_value_to_set, separators=(',', ':'))
        )
    # If there is a connection problem with the DB
    except Exception as err:
        siemplify.LOGGER.error("Exception was raised from the database.  ERROR: {}".format(err))
        siemplify.LOGGER.exception(err)
        raise


def platform_supports_chronicle(siemplify):
    if hasattr(siemplify, 'get_updated_sync_cases_metadata'):
        return True
