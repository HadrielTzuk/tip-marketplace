import requests
from ZohoDeskExceptions import ZohoDeskException


def validate_response(response, error_msg='An error occurred'):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {str} Default message to display on error
    """
    try:
        response.raise_for_status()
    except requests.HTTPError as error:
        try:
            response.json()
        except Exception:
            raise ZohoDeskException(f'{error_msg}: {error} {error.response.content}')

        response_json = response.json()

        if response_json.get('message'):
            errors = response_json.get('errors', [])
            if errors:
                errors_message = "\n".join([err.get('errorMessage') for err in errors])
                raise ZohoDeskException(
                    f"{response_json.get('message')}: {errors_message}"
                )
            raise ZohoDeskException(
                f"{response_json.get('message')}"
            )
        else:
            raise ZohoDeskException(
                f"{error_msg}: {error} {response.content}"
            )
