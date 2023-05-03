import json
from GoogleSecurityCommandCenterExceptions import GoogleSecurityCommandCenterException, \
    GoogleSecurityCommandCenterInvalidJsonException, GoogleSecurityCommandCenterInvalidProject
import datetime
from constants import SUCCESS_STATUSES, TIMEFRAME_MAPPING, TIME_FORMAT
from dateutil.relativedelta import relativedelta
from bs4 import BeautifulSoup


def validate_response(response_info, content, sensitive_data_arr=None, error_msg="An error occurred"):
    """
    Validate response
    :param response_info: {dict} The response info
    :param content: {dict} The response content
    :param sensitive_data_arr: {list} The list of sensitive data
    :param error_msg: {str} Default message to display on error
    """
    try:
        if not isinstance(response_info, dict) or response_info.get("status", "") not in SUCCESS_STATUSES:
            raise Exception

    except Exception:
        try:
            content = json.loads(content)
        except Exception:
            pass

        if isinstance(content, dict) and content.get("error", {}).get("message"):
            error_text = content.get("error", {}).get("message")
        else:
            error_text = BeautifulSoup(content, 'html.parser').p.text

        if sensitive_data_arr:
            raise GoogleSecurityCommandCenterException(encode_sensitive_data(str(
                "{error_msg}: {text}".format(
                    error_msg=error_msg,
                    text=error_text)
                ),
                sensitive_data_arr
            ))

        raise GoogleSecurityCommandCenterException(
            "{error_msg}: {text}".format(
                error_msg=error_msg,
                text=error_text)
        )

    return True


def encode_sensitive_data(message, sensitive_data_arr):
    """
    Encode sensitive data
    :param message: {str} The error message which may contain sensitive data
    :param sensitive_data_arr: {list} The list of sensitive data
    :return: {str} The error message with encoded sensitive data
    """
    for sensitive_data in sensitive_data_arr:
        message = message.replace(sensitive_data, encode_data(sensitive_data))

    return message


def encode_data(sensitive_data):
    """
    Encode string
    :param sensitive_data: {str} String to be encoded
    :return: {str} Encoded string
    """
    if len(sensitive_data) > 1:
        return f"{sensitive_data[0]}...{sensitive_data[-1]}"

    return sensitive_data


def parse_string_to_dict(string):
    """
    Parse json string to dict
    :param string: string to parse
    :return: {dict} parsed dict
    """
    try:
        return json.loads(string)
    except Exception:
        raise GoogleSecurityCommandCenterInvalidJsonException


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


def get_timestamp_from_range(range_string):
    """
    Get start time timestamp from range
    :param range_string: {str} Time range string
    :return: {int} start time timestamp
    """
    now = datetime.datetime.now()
    timeframe = TIMEFRAME_MAPPING.get(range_string)

    if timeframe == TIMEFRAME_MAPPING.get("Last Year"):
        start_time = now - relativedelta(years=1)
    elif timeframe == TIMEFRAME_MAPPING.get("Last Week"):
        start_time = now - datetime.timedelta(weeks=1)
    elif timeframe == TIMEFRAME_MAPPING.get("Last Month"):
        start_time = now - relativedelta(months=1)
    else:
        return None

    return int(start_time.timestamp()*1000)


def datetime_to_rfc3339(datetime_obj: datetime.datetime) -> str:
    """
    Convert datetime object to RFC 3999 representation
    :param datetime_obj: {datetime.datetime} The datetime object to convert
    :return: {str} The RFC 3999 representation of the datetime
    """
    return datetime_obj.strftime(TIME_FORMAT)


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get("OriginalIdentifier", entity.identifier)


def validate_request_id(id):
    """
    Helper function for validating ID
    :param id: id which function will check
    """
    if not id:
        raise GoogleSecurityCommandCenterInvalidProject
