"""
TIPCommon
=========

A TIP in-house replacment for siemplify built in SiemplifyUtils.py part of the SDK. Uncoupled to platform version.

Wraps `DataStream` module with read & write functions

"""
import copy
import datetime
import sys
from functools import reduce

import arrow
import chardet
from SiemplifyUtils import (
    convert_datetime_to_unix_time,
    convert_string_to_unix_time,
    unix_now,
    utc_now,
)

from .DataStream import DataStreamFactory


##########################
#       CONSTANTS        #
##########################

WHITELIST_FILTER = 1
BLACKLIST_FILTER = 2

UNIX_FORMAT = 1
DATETIME_FORMAT = 2

STORED_IDS_LIMIT = 1000
ACCEPTABLE_TIME_INTERVAL_IN_MINUTES = 5
TIMEOUT_THRESHOLD = 0.9

NUM_OF_HOURS_IN_DAY = 24
NUM_OF_HOURS_IN_3_DAYS = 72
NUM_OF_SEC_IN_SEC = 1
NUM_OF_MILLI_IN_SEC = 1000
NUM_OF_MILLI_IN_MINUTE = 60000

IDS_DB_KEY = 'ids'
IDS_FILE_NAME = 'ids.json'


########################################################################################
#            EXTRACT  METHODS              ##            EXTRACT  METHODS              #
########################################################################################

def extract_script_param(
    siemplify, input_dictionary, param_name, default_value=None, input_type=str,
    is_mandatory=False, print_value=False, remove_whitespaces=True
):
    """Extracts a script parameter from an input dictionary.

    Args:
        siemplify: The Siemplify object.
        input_dictionary: The input dictionary.
        param_name: The parameter name.
        default_value: The default value.
        input_type: The input type.
        is_mandatory: Whether the parameter is mandatory.
        print_value: Whether to print the value.
        remove_whitespaces: Whether to remove whitespaces from the value.

    Returns:
        The extracted value.
    """
    # internal param validation:
    if not siemplify:
        raise Exception("Parameter 'siemplify' cannot be None")

    if not param_name:
        raise Exception("Parameter 'param_name' cannot be None")

    if default_value and not (type(default_value) == input_type):
        raise Exception(
            "Given default_value of '{0}' doesn't match expected type {1}".format(
                default_value,
                input_type.__name__
            )
        )

    #  =========== start validation logic =====================
    value = input_dictionary.get(param_name)

    if not value:
        if is_mandatory:
            raise Exception(
                "Missing mandatory parameter {0}".format(param_name)
            )
        else:
            value = default_value
            siemplify.LOGGER.info(
                "Paramter {0} was not found or was empty, used default_value {1} instead".format(
                    param_name,
                    default_value
                )
            )
            return value

    if print_value:
        siemplify.LOGGER.info(u"{}: {}".format(param_name, value))

    # None values should not be converted.
    if value is None:
        return None

    if input_type == bool:
        lowered = str(value).lower()
        valid_lowered_bool_values = [
            str(True).lower(), 
            str(False).lower(),
            str(bool(None)).lower()
        ] # In Python - None and bool False are the same logicly

        if lowered not in valid_lowered_bool_values:
            raise Exception(
                "Paramater named {0}, with value {1} isn't a valid BOOL".format(
                    param_name,
                    value
                )
            )
        result = lowered == str(True).lower()
    elif input_type == int:
        result = int(value)
    elif input_type == float:
        result = float(value)
    elif input_type == str:
        result = str(value)
    elif input_type == unicode:
        result = value
    else:
        raise Exception(
            "input_type {0} isn't not supported for conversion".format(
                input_type.__name__
            )
        )

    if remove_whitespaces:
        return clean_result(result)

    return result


def extract_configuration_param(
    siemplify, provider_name, param_name, default_value=None, input_type=str,
    is_mandatory=False, print_value=False, remove_whitespaces=True
):
    """Extracts a configuration parameter value from the Integrations's configuration.

    Args:
        siemplify: The Siemplify object.
        provider_name: The Integration Identifier.
        param_name: The parameter name.
        default_value: The default value yo set in case there's no value in the configuration.
        input_type: The input type.
        is_mandatory: Whether the parameter is mandatory.
        print_value: Whether to print the value.
        remove_whitespaces: Whether to remove whitespaces from the value.
    
    Returns:
        The extracted value.
    """
    if not provider_name:
        raise Exception("provider_name cannot be None/empty")

    configuration = siemplify.get_configuration(provider_name)
    return extract_script_param(
        siemplify=siemplify,
        input_dictionary=configuration,
        param_name=param_name,
        default_value=default_value,
        input_type=input_type,
        is_mandatory=is_mandatory,
        print_value=print_value,
        remove_whitespaces=remove_whitespaces
    )


def extract_action_param(
    siemplify,
    param_name,
    default_value=None,
    input_type=str,
    is_mandatory=False,
    print_value=False,
    remove_whitespaces=True
):
    """Extracts an action parameter from the Siemplify object.

    Args:
        siemplify (Siemplify): The Siemplify object.
        param_name (str): The name of the parameter to extract.
        default_value (Any, optional): The default value to return if the parameter is not found.
        input_type (type, optional): The type of the parameter.
        is_mandatory (bool, optional): Whether the parameter is mandatory.
        print_value (bool, optional): Whether to print the value of the parameter.
        remove_whitespaces (bool, optional): Whether to remove whitespaces from the value of the parameter.

    Returns:
        Any: The value of the parameter.
    """
    return extract_script_param(
        siemplify=siemplify,
        input_dictionary=siemplify.parameters,
        param_name=param_name,
        default_value=default_value,
        input_type=input_type,
        is_mandatory=is_mandatory,
        print_value=print_value,
        remove_whitespaces=remove_whitespaces
    )


def extract_connector_param(
    siemplify,
    param_name,
    default_value=None,
    input_type=str,
    is_mandatory=False,
    print_value=False,
    remove_whitespaces=True
):
    """Extracts a connector parameter from the Siemplify object.

    Args:
        siemplify (Siemplify): The Siemplify object.
        param_name (str): The name of the parameter to extract.
        default_value (Any, optional): The default value to return if the parameter is not found.
        input_type (type, optional): The type of the parameter.
        is_mandatory (bool, optional): Whether the parameter is mandatory.
        print_value (bool, optional): Whether to print the value of the parameter.
        remove_whitespaces (bool, optional): Whether to remove whitespaces from the value of the parameter.

    Returns:
        Any: The value of the parameter.
    """
    return extract_script_param(
        siemplify=siemplify,
        input_dictionary=siemplify.parameters,
        param_name=param_name,
        default_value=default_value,
        input_type=input_type,
        is_mandatory=is_mandatory,
        print_value=print_value,
        remove_whitespaces=remove_whitespaces
    )


########################################################################################
#              DATA  METHODS               ##              DATA  METHODS               #
########################################################################################

def construct_csv(list_of_dicts):
    """Constructs a CSV from a list of dictionaries.

    Args:
        list_of_dicts (list[dict]): The list of dictionaries to add to the CSV.

    Returns:
        list[str]: The CSV formatted list.
    """
    csv_output = []
    if not list_of_dicts:
        return csv_output
    headers = reduce(set.union, map(set, map(dict.keys, list_of_dicts)))
    unicode_headers = []
    for header in headers:
        header = adjust_to_csv(header)
        header = get_unicode(header)
        unicode_headers.append(header)
    csv_output.append(u",".join(unicode_headers))
    for result in list_of_dicts:
        csv_row = []
        for header in headers:
            cell_value = result.get(header)
            cell_value = adjust_to_csv(cell_value)
            cell_value = get_unicode(cell_value)

            # Replace problematic commas
            cell_value = cell_value.replace(u',', u' ')
            # Append values to the row
            csv_row.append(cell_value)
        # Append row to the output
        csv_output.append(u",".join(csv_row))
    return csv_output


def adjust_to_csv(value):
    """Adjusts a value to be suitable for inclusion in a CSV.

    Args:
        value (Any): The value to adjust.

    Returns:
        str: The adjusted value.
    """
    if value is None:
        return ""
    return value


def dict_to_flat(target_dict):
    """
    Receives nested dictionary and returns it as a flat dictionary.

    Args:
        target_dict (dict): The dictionary to flatten.

    Returns:
        dict: The flattened dictionary.
    """
    target_dict = copy.deepcopy(target_dict)

    def expand(raw_key, raw_value):
        """
        Private recursive function to expand a nested dictionary.

        Args:
            raw_key (str): The key to expand.
            raw_value (str): The value to expand.

        Returns:
            list[tuple]: A list of tuples, each containing a key and a value.
        """
        key = raw_key
        value = raw_value
        if value is None:
            return [(get_unicode(key), u"")]
        elif isinstance(value, dict):
            # Handle dict type value
            return [(u"{0}_{1}".format(
                get_unicode(key),
                get_unicode(sub_key)
            ),
                     get_unicode(sub_value)) for sub_key, sub_value in
                    dict_to_flat(value).items()]
        elif isinstance(value, list):
            # Handle list type value
            count = 1
            l = []
            items_to_remove = []
            for value_item in value:
                if isinstance(value_item, dict):
                    # Handle nested dict in list
                    l.extend(
                        [(u"{0}_{1}_{2}".format(
                            get_unicode(key),
                            get_unicode(count),
                            get_unicode(sub_key)
                        ),
                          sub_value)
                         for sub_key, sub_value in
                         dict_to_flat(value_item).items()]
                    )
                    items_to_remove.append(value_item)
                    count += 1
                elif isinstance(value_item, list):
                    l.extend(
                        expand(
                            get_unicode(key) + u'_' + get_unicode(count),
                            value_item
                            )
                    )
                    count += 1
                    items_to_remove.append(value_item)

            for value_item in items_to_remove:
                value.remove(value_item)

            for value_item in value:
                l.extend(
                    [(get_unicode(key) + u'_' + get_unicode(count), value_item)]
                )
                count += 1

            return l
        else:
            return [(get_unicode(key), get_unicode(value))]

    items = [item for sub_key, sub_value in target_dict.items() for item in
             expand(sub_key, sub_value)]
    return dict(items)


def flat_dict_to_csv(
    flat_dict,
    property_header=u"Property",
    value_header=u"Value"
):
    """
    Turns a flat dictionary into a list of strings in CSV format. The `property_header` and `value_header` arguments are used to customize the CSV header.

    Args:
        flat_dict (dict): The dictionary to convert to CSV format.
        property_header (str): The header for the property column. Defaults to "Property".
        value_header (str): The header for the value column. Defaults to "Value".

    Returns:
        list: The list of strings in CSV format.
    """
    csv_format = []
    csv_head = u"{}, {}".format(property_header, value_header)
    csv_format.append(csv_head)
    for key, value in flat_dict.items():
        safe_key = get_unicode(key)
        safe_value = get_unicode(value)
        csv_format.append(u"{0},{1}".format(safe_key, safe_value))
    return csv_format


def add_prefix_to_dict(given_dict, prefix):
    """
    Adds a prefix to the keys of a given dictionary.

    Args:
        given_dict (dict): The dictionary to add the prefix to.
        prefix (str): The prefix to add.

    Returns:
        dict: The dictionary with the prefix added to the keys.
    """
    return {u'{0}_{1}'.format(get_unicode(prefix), get_unicode(key)): value for
            key, value in given_dict.items()}


def add_prefix_to_dict_keys(target_dict, prefix):
    """
    Adds a prefix to the keys of a given dictionary.

    Args:
        target_dict (dict): The dictionary to add the prefix to.
        prefix (str): The prefix to add.

    Returns:
        dict: The dictionary with the prefix added to the keys.
    """
    result_dict = {}
    for key, val in target_dict.iteritems():
        new_key = u"{0}_{1}".format(get_unicode(prefix), get_unicode(key))
        result_dict[new_key] = val

    return result_dict


def get_unicode(value):
    """
    Get the unicode of a value.

    Args:
        value (Any): The value to convert to unicode.

    Returns:
        unicode (unicode): The unicode representation of `value`.

    """
    if is_python_37():
        return str(value)
    if isinstance(value, unicode):
        return value
    if not isinstance(value, basestring):
        # Validate that the cell is a basestring. If not convert it to string
        try:
            value = str(value)
        except Exception:
            value = u"Unable to get text representation of object"
    if value is None:
        # If the value is empty, leave the cell empty
        value = u""
    if isinstance(value, str):
        try:
            value = value.decode("utf8")
        except UnicodeDecodeError:
            try:
                encoding = chardet.detect(value).get('encoding')
                value = value.decode(encoding)
            except Exception:
                value = u"Unable to decode value (unknown encoding)"

    return value


def string_to_multi_value(string_value, delimiter=',', only_unique=False):
    """
    Convert a string containing a comma-separated list of values to a list of values.

    Args:
        string_value (str): The string to convert.
        delimiter (str, optional): The delimiter to split the string on. Defaults to ','.
        only_unique (bool, optional): If True, only include unique values in the returned list. Defaults to False.

    Returns:
        list: The list of values.
    """
    if not string_value:
        return []
    values = [single_value.strip() for single_value in
              string_value.split(delimiter) if single_value.strip()]
    if only_unique:
        seen = set()
        return [value for value in values if
                not (value in seen or seen.add(value))]
    return values


def convert_comma_separated_to_list(comma_separated):
    """
    Convert a comma-separated string to a list of values.

    Args:
        comma_separated (str): The comma-separated string to convert.

    Returns:
        list: The list of values.
    """
    return [item.strip() for item in
            comma_separated.split(',')] if comma_separated else []


def convert_list_to_comma_string(values_list):
    """
    Convert a list of values to a comma-separated string.

    Args:
        values_list (list): The list of values to convert.

    Returns:
        str: The comma-separated string.
    """
    return ', '.join(str(v) for v in values_list) if values_list and isinstance(
        values_list,
        list
    ) else values_list


########################################################################################
#            UTILITY  METHODS              ##            UTILITY  METHODS              #
########################################################################################

def clean_result(value):
    """
    Strip the value from unnecessary spaces before or after the value.

    Args:
        value (str): The value to clean.

    Returns:
        str: A cleaned version of the original value.

    """
    try:
        return value.strip()
    except Exception:
        return value


def is_python_37():
    """
    Check if the python version of the system is 3.7 or above.

    Args:
        None.

    Returns:
        bool: True if the current python version is at least 3.7.

    """
    return sys.version_info >= (3, 7)


def platform_supports_db(siemplify):
    """
    Check if the platform supports database usage.

    Args:
        siemplify (object): The siemplify SDK object.

    Returns:
        bool: True if the siemplify SDK object has an attribute called "set_connector_context_property".

    """

    if hasattr(siemplify, 'set_connector_context_property'):
        return True
    return False


def is_empty_string_or_none(data):
    """
    Check if the data is an 'empty string' or 'None'.

    Args:
        data (str): The data to check.

    Returns:
        bool: True if the supplied data is 'None', or if it only contains an empty string "".

    """

    if data is None or data == "":
        return True
    return False


def cast_keys_to_int(data):
    """
    Cast the keys of a dictionary to integers.

    Args:
        data (dict): The data whose keys will be cast to ints.

    Returns:
        dict: A new dict with its keys as ints.

    """
    return {int(k): v for k, v in data.items()}


def none_to_default_value(value_to_check, value_to_return_if_none):
    """
    Check if the current value is None. If it is, replace it with another value. If not, return the original value.

    Args:
        value_to_check (dict/list/str): The value to check.
        value_to_return_if_none (dict/list/str): The value to return if `value_to_check` is None.

    Returns:
        dict/list/str: The original value of `value_to_check` if it is not None, or `value_to_return_if_none` if it is None.

    """
    if value_to_check is None:
        value_to_check = value_to_return_if_none
    return value_to_check


########################################################################################
#              READ  METHODS               ##              READ  METHODS               #
########################################################################################

def read_content(
    siemplify,
    file_name,
    db_key,
    default_value_to_return=None,
    identifier=None
):
    """
    Read the content of a `ConnectorStream` object.
    If the object contains no data, does not exist, return a default value

    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class.
        file_name: (str) The name of the file to be validated (in case the platform uses files)
        db_key: (str) The name of the key to be validated (in case the platform uses database)
        default_value_to_return: (dict/list/str) The default value to be set in case a new file/key is created.
                                    If no value is supplied, an internal default value of {} (dict) will be set as
                                    the new default value.
        identifier: (str) The connector's identifier attribute.

    Returns:
        (dict) The content inside the `DataStream` object, the content passes through `json.loads` before returning.
    """

    data = DataStreamFactory.get_stream_object(
        file_name,
        db_key,
        siemplify,
        identifier
    )

    default_value_to_return = none_to_default_value(default_value_to_return, {})

    return data.read_content(default_value_to_return)


def read_ids(
    siemplify,
    default_value_to_return=None,
    identifier=None,
    ids_file_name=IDS_FILE_NAME,
    db_key=IDS_DB_KEY
):
    """
    Read IDs from a `ConnectorStream` object.
    If the object contains no data, does not exist, return a default value

    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class.
        default_value_to_return: (dict/list/str) The default value to be set in case a new file/key is created.
                                    If no value is supplied, an internal default value of [] (list) will be set as
                                    the new default value.
        identifier: (str) The connector's identifier attribute.
        ids_file_name: (str) The file name where IDs should be saved when `FileStream` object had been created.
        db_key: (str) The key name where IDs should be saved when `FileStream` object had been created.

    Returns:
        (list) List of IDs inside the `DataStream` object, the content passes through `json.loads` before returning.
    """

    default_value_to_return = none_to_default_value(default_value_to_return, [])

    return read_content(
        siemplify,
        ids_file_name,
        db_key,
        default_value_to_return,
        identifier
    )


def read_ids_by_timestamp(
    siemplify,
    offset_in_hours=NUM_OF_HOURS_IN_3_DAYS,
    default_value_to_return=None,
    convert_to_milliseconds=False,
    cast_keys_to_integers=False,
    offset_is_in_days=False,
    identifier=None,
    ids_file_name=IDS_FILE_NAME,
    db_key=IDS_DB_KEY
):
    """
    Read IDs from a `ConnectorStream` object.
    If the object contains no data, does not exist, return a default value

    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class.
        offset_in_hours: (int) The IDs time limit (offset value) in hours.
        convert_to_milliseconds: (bool) Transform each ID's timestamp (unix) from seconds to milliseconds.
        cast_keys_to_integers: (bool) Cast the keys to integers.
        default_value_to_return: (dict/list/str) The default value to be set in case a new file/key is created.
        offset_is_in_days: (bool) If the offset supplied to this method is in days, please mark this as True for
                                    converting the offset days into hours.
        identifier: (str) The connector's identifier attribute.
        ids_file_name: (str) The file name where IDs should be saved when `FileStream` object had been created.
        db_key: (str) The key name where IDs should be saved when `FileStream` object had been created.

    Returns:
        (list) List of IDs inside the `DataStream` object, the content passes through `json.loads` before returning.
    """

    existing_ids = read_content(
        siemplify,
        ids_file_name,
        db_key,
        default_value_to_return,
        identifier
    )

    try:
        filtered_ids = filter_old_ids_by_timestamp(
            ids=existing_ids,
            offset_in_hours=offset_in_hours,
            convert_to_milliseconds=convert_to_milliseconds,
            offset_is_in_days=offset_is_in_days
        )
        if cast_keys_to_integers:
            return cast_keys_to_int(filtered_ids)

        return filtered_ids

    except Exception as e:
        siemplify.LOGGER.error('Unable to read ids file: {}'.format(e))
        siemplify.LOGGER.exception(e)

        default_value_to_return = none_to_default_value(
            default_value_to_return,
            {}
        )
        return default_value_to_return


########################################################################################
#              WRITE  METHODS              ##              WRITE  METHODS              #
########################################################################################

def write_content(
    siemplify,
    content_to_write,
    file_name,
    db_key,
    default_value_to_set=None,
    identifier=None
):
    """Writes content into a `ConnectorStream` object.

    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class.
        content_to_write: (dict/list/str) The content to be written to the dedicated data stream.
        file_name: (str) The name of the file to be written to.
        db_key: (str) The name of the key to be written to.
        default_value_to_set: (dict/list/str) The default value to be set in case a new file/key is created.
        identifier: (str) The connector's identifier attribute.

    Returns:
        None
    """
    data = DataStreamFactory.get_stream_object(
        file_name,
        db_key,
        siemplify,
        identifier
    )

    default_value_to_set = none_to_default_value(default_value_to_set, {})

    data.write_content(content_to_write, default_value_to_set)


def write_ids(
    siemplify,
    ids,
    default_value_to_set=None,
    stored_ids_limit=STORED_IDS_LIMIT,
    identifier=None,
    ids_file_name=IDS_FILE_NAME,
    db_key=IDS_DB_KEY
):
    """Writes the last 1,000 IDs into a `ConnectorStream` object.

    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class.
        ids: (list/str) The IDs to be written to the dedicated data stream.
        default_value_to_set: (dict/list/str) The default value to be set in case a new file/key is created.
        stored_ids_limit: (int) The number of recent IDs from the existing ids which will be written.
        identifier: (str) The connector's identifier attribute.
        ids_file_name: (str) The file name where IDs should be saved when `FileStream` object had been created.
        db_key: (str) The key name where IDs should be saved when `FileStream` object had been created.

    Returns:
        None
    """

    default_value_to_set = none_to_default_value(default_value_to_set, [])

    ids = ids[-stored_ids_limit:]
    write_content(
        siemplify,
        ids,
        ids_file_name,
        db_key,
        default_value_to_set,
        identifier
    )


def write_ids_with_timestamp(
    siemplify,
    ids,
    default_value_to_set=None,
    identifier=None,
    ids_file_name=IDS_FILE_NAME,
    db_key=IDS_DB_KEY
):
    """Writes IDs into a `ConnectorStream` object with a timestamp.

    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class.
        ids: (dict/list/str) The IDs to be written to the dedicated data stream.
        default_value_to_set: (dict/list/str) The default value to be set in case a new file/key is created.
        identifier: (str) The connector's identifier attribute.
        ids_file_name: (str) The file name where IDs should be saved when `FileStream` object had been created.
        db_key: (str) The key name where IDs should be saved when `FileStream` object had been created.

    Returns:
        None
    """

    default_value_to_set = none_to_default_value(default_value_to_set, {})

    write_content(
        siemplify,
        ids,
        ids_file_name,
        db_key,
        default_value_to_set,
        identifier
    )


########################################################################################
#              TIME  METHODS               ##              TIME  METHODS               #
########################################################################################

def validate_timestamp(
    last_run_timestamp,
    offset_in_hours,
    offset_is_in_days=False
):
    """Validates timestamp in range.

    Args:
        last_run_timestamp (datetime): The last run timestamp.
        offset_in_hours (int): The time limit in hours.
        offset_is_in_days (bool, optional): Whether the offset is in days. Defaults to False.

    Raises:
        ValueError: If the timestamp is not valid.

    Returns:
        datetime: The validated timestamp.
    """

    current_time = utc_now()

    if offset_is_in_days:
        offset_in_hours = offset_in_hours * NUM_OF_HOURS_IN_DAY

    if current_time - last_run_timestamp > datetime.timedelta(
        hours=offset_in_hours
    ):
        return current_time - datetime.timedelta(hours=offset_in_hours)
    else:
        return last_run_timestamp


def save_timestamp(
    siemplify,
    alerts,
    timestamp_key='timestamp',
    incrementation_value=0,
    log_timestamp=True,
    convert_timestamp_to_micro_time=False,
    convert_a_string_timestamp_to_unix=False
):
    """Saves last timestamp for given alerts.

    Args:
        siemplify (obj): An instance of the SDK `SiemplifyConnectorExecution` class.
        alerts (dict): The list of alerts to find the last timestamp.
        timestamp_key (str, optional): The key for getting timestamp from alert. Defaults to 'timestamp'.
        incrementation_value (int, optional): The value to increment last timestamp by milliseconds. Defaults to 0.
        log_timestamp (bool, optional): Whether log timestamp or not. Defaults to True.
        convert_timestamp_to_micro_time (bool, optional): Whether to convert timestamp to micro time. Defaults to False.
        convert_a_string_timestamp_to_unix (bool, optional): Whether to convert a string timestamp to unix. Defaults to False.

    Returns:
        bool: Whether the timestamp is updated.
    """

    if not alerts:
        siemplify.LOGGER.info(
            'Timestamp is not updated since no alerts fetched'
        )
        return False

    if convert_a_string_timestamp_to_unix:
        alerts = sorted(
            alerts,
            key=lambda alert: convert_string_to_unix_time(
                getattr(alert, timestamp_key)
            )
        )
        last_timestamp = convert_string_to_unix_time(
            getattr(alerts[-1], timestamp_key)
        ) + incrementation_value
    else:
        alerts = sorted(
            alerts,
            key=lambda alert: int(getattr(alert, timestamp_key))
        )
        last_timestamp = int(
            getattr(alerts[-1], timestamp_key)
        ) + incrementation_value

    last_timestamp = last_timestamp * NUM_OF_MILLI_IN_SEC if convert_timestamp_to_micro_time else last_timestamp
    if log_timestamp:
        siemplify.LOGGER.info('Last timestamp is :{}'.format(last_timestamp))

    siemplify.save_timestamp(new_timestamp=last_timestamp)
    return True


def get_last_success_time(
    siemplify,
    offset_with_metric,
    time_format=DATETIME_FORMAT,
    print_value=True,
    microtime=False
):
    """Get last success time datetime.

    Args:
        siemplify (obj): An instance of the SDK SiemplifyConnectorExecution class.
        offset_with_metric (dict): The metric and value. Ex: {'hours': 1}
        time_format (int): The format of the output time. Ex: DATETIME, UNIX
        print_value (bool, optional): Whether to print the value or not. Defaults to True.
        microtime (bool, optional): Whether to return unix time including microtime. Defaults to False.

    Returns:
        time: The last success time.
    """

    last_run_timestamp = siemplify.fetch_timestamp(datetime_format=True)
    offset = datetime.timedelta(**offset_with_metric)
    current_time = utc_now()
    # Check if first run
    datetime_result = current_time - offset if current_time - last_run_timestamp > offset else last_run_timestamp
    unix_result = convert_datetime_to_unix_time(datetime_result)
    unix_result = unix_result if not microtime else int(
        unix_result / NUM_OF_MILLI_IN_SEC
        )

    if print_value:
        siemplify.LOGGER.info(
            'Last success time. Date time:{}. Unix:{}'.format(
                datetime_result,
                unix_result
            )
        )
    return unix_result if time_format == UNIX_FORMAT else datetime_result


def siemplify_fetch_timestamp(siemplify, datetime_format=False, timezone=False):
    """Fetches timestamp from Siemplify.

    Args:
        siemplify (obj): An instance of the SDK `SiemplifyConnectorExecution` class.
        datetime_format (bool, optional): Whether to return the timestamp in datetime format. Defaults to False.
        timezone (bool, optional): Whether to return the timestamp in UTC timezone. Defaults to False.

    Returns:
        The timestamp.
    """
    last_time = siemplify.fetch_timestamp(
        datetime_format=datetime_format,
        timezone=timezone
    )
    if last_time == 0:
        siemplify.LOGGER.info(
            'Timestamp key does not exist in the database. Initiating with value: 0.'
        )
    return last_time


def siemplify_save_timestamp(
    siemplify,
    datetime_format=False,
    timezone=False,
    new_timestamp=unix_now()
):
    """Saves timestamp to Siemplify.

    Args:
        siemplify (obj): An instance of the SDK `SiemplifyConnectorExecution` class.
        datetime_format (bool, optional): Whether to save the timestamp in datetime format. Defaults to False.
        timezone (bool, optional): Whether to save the timestamp in UTC timezone. Defaults to False.
        new_timestamp (int): The new timestamp to save.

    Returns:
        None
 """
    siemplify.save_timestamp(
        datetime_format=datetime_format,
        timezone=timezone,
        new_timestamp=new_timestamp
    )


def is_approaching_timeout(
    connector_starting_time,
    python_process_timeout,
    timeout_threshold=TIMEOUT_THRESHOLD
):
    """Checks if a timeout is approaching.

    Args:
        connector_starting_time (int): The time the connector started.
        python_process_timeout (int): The maximum amount of time the connector is allowed to run.
        timeout_threshold (float): The threshold at which the connector is considered to be approaching a timeout. Defaults to `TIMEOUT_THRESHOLD`.

    Returns:
        `True` if the connector is approaching a timeout, `False` otherwise.
    """
    processing_time_ms = unix_now() - connector_starting_time
    return processing_time_ms > python_process_timeout * NUM_OF_MILLI_IN_SEC * timeout_threshold


########################################################################################
#               OTHER  METHODS             ##               OTHER  METHODS             #
########################################################################################

def validate_existence(
    file_name,
    db_key,
    default_value_to_set,
    siemplify,
    identifier=None
):
    """
    Validates the existence of a `DataStream` object.
    If it does not exist, initiate it with default value.
    
    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class
        file_name: (str) the name of the file to be validated (in case the platform uses files)
        db_key: (str) the name of the key to be validated (in case the platform uses database)
        default_value_to_set: (dict/list/str) the default value to be set in case a new file/key is created.
        *Note that the default value passes through `json.dumps` before getting written
        identifier: The connector's identifier attribute.
            * If no value is supplied (therefore the default value `None` is used),
            the default identifier will be given using the current siemplify object:
            (`self.siemplify.context.connector_info.identifier`).
    
    Returns:
        None
    """

    data = DataStreamFactory.get_stream_object(
        file_name,
        db_key,
        siemplify,
        identifier
    )
    data.validate_existence(default_value_to_set)


def is_overflowed(siemplify, alert_info, is_test_run):
    """
    Checks if overflowed.
    
    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class
        alert_info: (AlertInfo)
        is_test_run: (bool) Whether test run or not.
    
    Returns:
        `True` if the alert is overflowed, `False` otherwise.
    """
    try:
        return siemplify.is_overflowed_alert(
            environment=alert_info.environment,
            alert_identifier=alert_info.ticket_id,
            alert_name=alert_info.rule_generator,
            product=alert_info.device_product
        )

    except Exception as err:
        siemplify.LOGGER.error(
            'Error validation connector overflow, ERROR: {}'.format(err)
        )
        siemplify.LOGGER.exception(err)
        if is_test_run:
            raise

    return False


def filter_old_ids(alert_ids, existing_ids):
    """
    Filters ids that were already processed.
    
    Args:
        alert_ids: (list) List of new ids from the alert to filter
        existing_ids: (list) List of ids to compare to
    
    Returns:
        (list) List of filtered ids
    """
    new_alert_ids = []

    for alert_id in alert_ids:
        if alert_id not in existing_ids.keys():
            new_alert_ids.append(alert_id)

    return new_alert_ids


def filter_old_ids_by_timestamp(
    ids,
    offset_in_hours,
    convert_to_milliseconds,
    offset_is_in_days
):
    """Filters ids that are older than IDS_HOURS_LIMIT hours.

    Args:
        ids: (dict) The ids to filter.
        offset_in_hours: (int) The IDs time limit (offset value) in hours.
        offset_is_in_days: (bool) If the offset supplied to this method is in days, please mark this as True for
                            converting the offset days into hours.
        convert_to_milliseconds: (bool) Transform each ID's timestamp (unix) from seconds to milliseconds.

    Returns:
        (dict) The filtered ids.
    """
    filtered_ids = {}
    milliseconds = NUM_OF_MILLI_IN_SEC if convert_to_milliseconds else NUM_OF_SEC_IN_SEC

    if offset_is_in_days:
        offset_in_hours = offset_in_hours * NUM_OF_HOURS_IN_DAY

    for alert_id, timestamp in ids.items():
        if timestamp > arrow.utcnow().shift(
            hours=-offset_in_hours
        ).timestamp * milliseconds:
            filtered_ids[alert_id] = timestamp

    return filtered_ids


def filter_old_alerts(siemplify, alerts, existing_ids, id_key="alert_id"):
    """Filters alerts that were already processed.

    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class.
        alerts: (list) List of Alert objects.
        existing_ids: (list) List of ids to filter.
        id_key: (str) The key of identifier. The key under which the ids can be found in the alert. Default is "alert_id".

    Returns:
        (list) List of filtered Alert objects.
    """
    filtered_alerts = []

    for alert in alerts:
        ids = getattr(alert, id_key)

        if ids not in existing_ids:
            filtered_alerts.append(alert)
        else:
            siemplify.LOGGER.info(
                "The alert {} skipped since it has been fetched before".format(
                    ids
                )
            )

    return filtered_alerts


def pass_whitelist_filter(
    siemplify,
    whitelist_as_a_blacklist,
    model,
    model_key,
    whitelist=None
):
    """Determines whether a values from a key in a model pass the whitelist filter.

    Args:
        siemplify: (obj) An instance of the SDK `SiemplifyConnectorExecution` class.
        whitelist_as_a_blacklist: (bool) The value of the Connector's input checkbox `Use whitelist as blacklist`.
        model: (obj) An alert object of some type from which to extract the specific type/id that will be matched
                    against the whitelist.
        model_key: (str) The key (attribute) whose value is the specific type/id that will be matched against
                    the whitelist.
        whitelist: (Iterable) The list from which to search if a value is in order to determine whether it passes
                    the filter. If no value is provided the default will be the full connector's whitelist
                    (as can be seen in Siemplify's UI).

    Returns:
        (bool) True if the model passed the filter successfully else False.
    """
    # whitelist filter
    whitelist = whitelist or siemplify.whitelist
    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    model_value = getattr(model, model_key)
    model_values = model_value if isinstance(model_value, list) else [
        model_value]

    if whitelist:
        for value in model_values:
            if whitelist_filter_type == BLACKLIST_FILTER and value in whitelist:
                siemplify.LOGGER.info(
                    "'{}' did not pass blacklist filter.".format(value)
                )
                return False

            if whitelist_filter_type == WHITELIST_FILTER and value not in whitelist:
                siemplify.LOGGER.info(
                    "'{}' did not pass whitelist filter.".format(value)
                )
                return False

    return True
