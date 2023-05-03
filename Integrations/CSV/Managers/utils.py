import os
import json
import math
import codecs
from exceptions import CSVEncodingException
from TIPCommon import validate_map_file
from EnvironmentCommon import EnvironmentHandle
from SiemplifyUtils import convert_datetime_to_unix_time, convert_string_to_datetime


def string_to_multi_value(string_value, delimiter=',', only_unique=False):
    """
    String to multi value.
    :param string_value: {str} String value to convert multi value.
    :param delimiter: {str} Delimiter to extract multi values from single value string.
    :param only_unique: {bool} include only uniq values
    :return: {dict} fixed dictionary.
    """
    if not string_value:
        return []
    values = [single_value.strip() for single_value in string_value.split(delimiter) if single_value.strip()]
    if only_unique:
        seen = set()
        return [value for value in values if not (value in seen or seen.add(value))]
    return values


def get_value_for_search(column_name):
    if isinstance(column_name, str):
        return column_name.lower()

    return column_name


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


def replace_spaces_with_underscore(value):
    """
    Remove spaces from string
    :param value: {str}
    :return: {str} string with underscores instead of spaces
    """
    return value.replace(' ', '_')


def get_existing_column_names(df_item_info, columns_to_check):
    return list(filter(lambda field: field in df_item_info.columns, columns_to_check))


def get_encodings_or_raise(siemplify, encodings):
    """
    Validate given encodings.
    :param siemplify: {Siemplify}
    :param encodings: {list} List of file encoding types
    :return valid_encodings: {list} List of only valid encoding types from the list given by user
    """
    valid_encodings = []
    for encoding in encodings:
        try:
            codecs.lookup(encoding)
            valid_encodings.append(encoding)
        except LookupError as e:
            siemplify.LOGGER.error(f"Given encoding type {encoding} doesn't exist, this type won't be used for "
                                   "decoding your CSV files.")
            siemplify.LOGGER.exception(e)
    if not valid_encodings:
        raise CSVEncodingException('Provided encodings are invalid. Please check the spelling.')
    return valid_encodings


# Move to TIPCommon
def get_environment_common(siemplify, environment_field_name, environment_regex_pattern, map_file='map.json'):
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


def calculate_row_time(siemplify, *, row, csv_path, time_field_name, time_field_timezone):
    """
    Calculate record time in unix time
    :param siemplify: siemplify connector instance
    :param row: {dict} csv record data
    :param csv_path: {str} csv file path
    :param time_field_name: {str} field name - from where to fetch the time
    :param time_field_timezone: {str} Timezone in which the time field is
    :return: {long} record time
    """

    # Get file time
    file_time = int(os.path.getctime(csv_path)) * 1000  # The function return seconds(milliseconds required).
    record_time = row.get(time_field_name, int(file_time))

    try:
        # Check if time is in unix time
        time = int(record_time)
    except:
        try:
            # Check if time is time format
            time = convert_datetime_to_unix_time(
                convert_string_to_datetime(record_time, timezone_str=time_field_timezone))
            siemplify.LOGGER.info(f'Convert time to unix time. Before: {record_time}. After: {time}')
        except Exception as e:
            siemplify.LOGGER.error('Failed to convert time: {0} to unix time.'.format(record_time))
            siemplify.LOGGER.exception(e)
            time = 1

    return time


CUSTOM_CONFIGURATION_FILE_NAME = 'severity_map_config.json'
DEFAULT_SEVERITY_VALUE = 50
CUSTOM_MAPPING_CONFIGURATION = {}
CONFIGURATION_DATA = {}


def load_custom_severity_configuration(severity_field_name, file_path=CUSTOM_CONFIGURATION_FILE_NAME):
    global DEFAULT_SEVERITY_VALUE
    global CUSTOM_MAPPING_CONFIGURATION
    global CONFIGURATION_DATA

    conf_data = {}
    if os.path.isfile(file_path):
        with open(file_path, 'r') as f:
            try:
                conf_data = json.load(f)
            except:
                pass

    DEFAULT_SEVERITY_VALUE = conf_data.get('Default', DEFAULT_SEVERITY_VALUE)
    CUSTOM_MAPPING_CONFIGURATION = conf_data.get(severity_field_name, CUSTOM_MAPPING_CONFIGURATION)

    with open(file_path, 'w') as f:
        conf_data = {
            'Default': DEFAULT_SEVERITY_VALUE
        }
        if severity_field_name:
            conf_data[severity_field_name] = CUSTOM_MAPPING_CONFIGURATION
        CONFIGURATION_DATA = conf_data
        f.write(json.dumps(conf_data, indent=4))


def map_severity_value(severity_field_name, alert_data):
    """
    The function calculates case priority by the Priority Map.
    :param severity_field_name: {str} severity field name
    :param alert_data: {dict} flat event data
    :return: {int} calculated Siemplify alarm priority
    """
    default_severity = severity_field_name or DEFAULT_SEVERITY_VALUE

    if not severity_field_name:
        return default_severity

    severity_value = alert_data.get(severity_field_name, DEFAULT_SEVERITY_VALUE)
    severity_score = DEFAULT_SEVERITY_VALUE
    try:
        severity_score = math.ceil(float(severity_value))
    except:
        severity_dict = CONFIGURATION_DATA.get(severity_field_name)
        if severity_dict:
            severity_score = severity_dict.get(severity_value) or DEFAULT_SEVERITY_VALUE

    return min(100, max(-1, severity_score))


def list_of_dict_to_single_dict(list_of_dict, join_str=','):
    """
    Convert list of dict to single dict with multiple values joined by join_str.
    :param list_of_dict: {list} list of dicts
    :param join_str: {str} the string to join multiple values, if None value will be list
    :return: {dict} result dict
    """
    result_dict = {}
    for single_dict in list_of_dict:
        for key, value in single_dict.items():
            previous_value = result_dict.get(key, set())
            previous_value.add(value)
            result_dict[key] = previous_value
    if join_str:
        return {key: join_str.join(value) for key, value in result_dict.items()}
    return result_dict

