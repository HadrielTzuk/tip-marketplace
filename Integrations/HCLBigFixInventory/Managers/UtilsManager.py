import requests
from HCLBigFixInventoryExceptions import HCLBigFixInventoryException


def validate_response(response, sensitive_data=None, error_msg="An error occurred"):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param sensitive_data: {list} The list of sensitive data
    :param error_msg: {str} Default message to display on error
    """
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        if sensitive_data:
            raise HCLBigFixInventoryException(encode_sensitive_data(str(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)),
                sensitive_data
            ))

        raise HCLBigFixInventoryException(
            "{error_msg}: {error} {text}".format(
                error_msg=error_msg,
                error=error,
                text=error.response.content)
        )

    return True


def encode_sensitive_data(message, sensitive_data):
    """
    Encode sensitive data
    :param message: {str} The message which may contain sensitive data
    :param sensitive_data: {list} The list of sensitive data
    :return: {str} The message with encoded sensitive data
    """
    for item in sensitive_data:
        message = message.replace(item, encode_data(item))

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


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)
