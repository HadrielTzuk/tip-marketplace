import re

import requests

from AzureADIdentityProtectionExceptions import AzureADIdentityProtectionGeneralException


VALID_EMAIL_REGEXP = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'


def validate_response(response, error_msg='An error occurred'):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {unicode} Default message to display on error
    """
    try:
        response.raise_for_status()
        if "text/html" in response.headers.get("content-type", []):
            raise Exception("Invalid API root provided")
    except requests.HTTPError as error:
        try:
            response.json()
        except Exception:
            raise AzureADIdentityProtectionGeneralException(f'{error_msg}: {error} {error.response.content}')

        api_error = response.json().get('error', {})
        if isinstance(api_error, dict):
            raise AzureADIdentityProtectionGeneralException(
                f"{error_msg}: {error} {api_error.get('message') or response.content}"
            )
        raise AzureADIdentityProtectionGeneralException(
                f"{error_msg}: {error} {response.json().get('error_description') or response.content}"
            )


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


def is_valid_email(user_name):
    """
    Check if the user_name is valid email.
    :param user_name: {str} User name
    :return: {bool} True if valid email, else False
    """
    return bool(re.search(VALID_EMAIL_REGEXP, user_name))
