import requests
from TrendMicroVisionOneExceptions import TrendMicroVisionOneException
from typing import Any


def validate_response(response, error_msg="An error occurred"):
    """
    Validate response
    Args:
        response (requests.Response): The response to validate
        error_msg (str): Default message to display on error

    Returns:
        True, if successful, TrendMicroVisionOneException otherwise
    """
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        try:
            error_content = response.json()
            error_message = error_content["error"]["message"]
            raise TrendMicroVisionOneException(error_message)

        except (ValueError, KeyError):
            pass

        raise TrendMicroVisionOneException(
            "{error_msg}: {error} {text}".format(
                error_msg=error_msg,
                error=error,
                text=error.response.content)
        )


def get_entity_original_identifier(entity: Any) -> str:
    """
    Helper function for getting entity original identifier
    Args:
        entity: entity from which function will get original identifier

    Returns:
        original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)
