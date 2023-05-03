import requests


def validate_response(response, error_msg='An error occurred'):
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
