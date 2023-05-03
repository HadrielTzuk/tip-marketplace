import requests
from SiemplifyUtils import unix_now
from ipaddress import ip_address, IPv4Address
from constants import IPV4_TYPE, IPV6_TYPE, ASYNC_ACTION_TIMEOUT_THRESHOLD_MS
from exceptions import BadRequestException


def validate_response(response, error_msg="An error occurred"):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {str} Default message to display on error
    """
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        if response.status_code == 400:
            raise BadRequestException('{error_msg}: {error} {text}'.format(
                error_msg=error_msg,
                error=error,
                text=error.response.content))

        raise Exception(
            '{error_msg}: {error} {text}'.format(
                error_msg=error_msg,
                error=error,
                text=error.response.content)
        )

    return True


def get_dict_from_string(string):
    """
    Convert key:value string to dictionary
    :param string: {str} The string to convert
    :return: {dict} The converted dictionary
    """
    res = []

    for sub in string.split(','):
        if ':' in sub:
            res.append(map(str.strip, sub.split(':', 1)))

    return dict(res)


def get_ip_type(ip):
    """
    Check if ip is IPv4 or IPv6 or Invalid
    :param ip: {str} The given ip to check
    :return: {str} The type of ip
    """
    try:
        return IPV4_TYPE if type(ip_address(ip)) is IPv4Address else IPV6_TYPE
    except ValueError:
        pass


def is_action_approaching_timeout(python_process_timeout):
    """
    Check if a action script timeout is approaching.
    :param python_process_timeout: {int} The python process timeout
    :return: {bool} True if timeout is approaching, otherwise False
    """
    return unix_now() >= python_process_timeout - ASYNC_ACTION_TIMEOUT_THRESHOLD_MS


def hours_to_milliseconds(hours):
    """
    Convert hours to milliseconds
    :param hours: {int} Value in hours
    :return: {int} Converted value to milliseconds
    """
    return hours * 60 * 60 * 1000
