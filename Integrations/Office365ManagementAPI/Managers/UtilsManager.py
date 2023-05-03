import re

import requests

STORED_IDS_LIMIT = 3000
TIMEOUT_THRESHOLD = 0.9


def validate_response(response, error_msg="An error occurred"):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {str} Default message to display on error
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


def mask_string(string):
    """
    Mask given string
    :param string: {str} The string to mask
    :return: {str} The masked string
    """
    string = re.sub("\d", "0", string)
    string = re.sub("[a-zA-Z]", "X", string)
    return string


def get_milliseconds_from_minutes(minutes):
    """
    Get milliseconds from minutes
    :param minutes: {int} The minutes
    :return: {int} The milliseconds
    """
    return minutes * 60 * 1000
