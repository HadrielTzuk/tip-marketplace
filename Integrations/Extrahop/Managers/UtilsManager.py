import requests
from ExtrahopExceptions import ExtrahopException


def validate_response(response, error_msg='An error occurred'):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {unicode} Default message to display on error
    """
    try:
        response.raise_for_status()
    except requests.HTTPError as error:
        try:
            response.json()
        except Exception:
            raise ExtrahopException(f'{error_msg}: {error} {error.response.content}')

        raise ExtrahopException(
            f"{error_msg}: {error} {response.json().get('message') or response.content}"
        )


def pass_severity_filter(siemplify, alert, lowest_severity):
    # severity filter
    if lowest_severity and alert.risk_score < lowest_severity:
        siemplify.LOGGER.info('Detection with risk score: {} did not pass filter. Lowest risk score to fetch is '
                              '{}.'.format(alert.risk_score, lowest_severity))
        return False
    return True
