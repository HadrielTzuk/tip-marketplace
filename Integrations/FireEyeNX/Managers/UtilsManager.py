import ipaddress
import requests

from FireEyeNXConstants import (
    IPV4_MASK
)


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


def mask_ip_address(address: str) -> str:
    """
    Mask given IP Version 4. If given address already masked return it.
    :param address: {str} ip address of version 4 that needs to be masked
    :return: {str} masked ip address

    Note: function does not validate ip addresses
    """
    try:
        address = address.strip()
        ip_addr = ipaddress.ip_address(address)  # if masked/invalid this will raise an exception
        if ip_addr.version == 4:
            return address + IPV4_MASK
    except Exception:
        return address
