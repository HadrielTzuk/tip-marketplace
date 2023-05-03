import json
from typing import List, Any

from SiemplifyUtils import unix_now
from consts import (
    COMMA_SPACE,
    ASYNC_ACTION_TIMEOUT_THRESHOLD_MS
)
from datamodels import FilterLogicParam

from exceptions import InvalidJSONFormatException


def get_filtered_objects(objs: List[Any], attribute: str, filter_logic: str, filter_value: str):
    """
    Get filtered objects
    :param objs: [{obj}] List of objects to filter
    :param attribute: {str} Objects attribute to filter
    :param filter_logic: {str} Enum value of Filter logic parameter
    :param filter_value: {str} Value to use in the filter
    :return: {[obj]} List of filtered objects
    """
    if filter_logic == FilterLogicParam.Equal.value:
        return list(filter(lambda x: getattr(x, attribute) == filter_value, objs))
    elif filter_logic == FilterLogicParam.Contains.value:
        return list(filter(lambda x: filter_value in getattr(x, attribute), objs))
    else:
        raise Exception(
            f"Invalid \"Filter Logic\" parameter was provided. Possible values are: {COMMA_SPACE.join([f.value for f in FilterLogicParam])}")


def is_action_approaching_timeout(python_process_timeout):
    """
    Check if a action script timeout is approaching.
    :param python_process_timeout: {int} The python process timeout
    :return: {bool} True if timeout is approaching, otherwise False
    """
    return unix_now() >= python_process_timeout - ASYNC_ACTION_TIMEOUT_THRESHOLD_MS


def remove_none_values(origin_dict):
    """
    Remove keys from dictionary that has the value None
    :param origin_dict: {dict} Dictionary to process
    :return: {dict} Dictionary without keys that have the value None
    """
    return {k: v for k, v in origin_dict.items() if v is not None}


def parse_string_to_dict(string):
    """
    Parse json string to dict
    :param string: string to parse
    :return: {dict} parsed dict
    """
    try:
        return json.loads(string)
    except Exception as err:
        raise InvalidJSONFormatException(f"Unable to parse provided json. Error is: {err}")
