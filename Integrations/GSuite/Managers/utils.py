import json

import consts


def remove_empty_kwargs(**kwargs) -> dict:
    """
    Remove keys from dictionary that has empty value (None, empty list, dict, str..)
    :param kwargs: key value arguments
    :return: dictionary without keys that have the value None
    """
    return {k: v for k, v in kwargs.items() if v or isinstance(v, bool)}


def map_boolean_query_param(param: bool) -> str:
    """
    Map boolean query parameter. Used in list-users API call to list users.
    :param param: {bool} True or False
    :return: {str} 'true' if param is True and 'false' if param is False
    """
    return consts.TRUE if param else consts.FALSE


def map_str_query_param(param: str):
    """
    Map string query parameter. String query parameter must escape single quotes characters inside the string, and replace double quotes to single quotes on both ends of the string.
    For example: "my tip" -> 'my tip', 'my"s tip' -> 'my"s tip', "my's tip" -> 'my\'s tip'
    :param param: {str} the parameter to map
    :return: {str} mapped string
    """
    try:
        escaped_json = param.replace("'", "\\'")
        return f"'{escaped_json}'"
    except Exception:
        return param
