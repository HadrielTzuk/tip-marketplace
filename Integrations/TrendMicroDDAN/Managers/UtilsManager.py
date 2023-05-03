import os
import requests
from TrendMicroDDANExceptions import TrendMicroDDANException, TrendMicroDDANNotFoundException
import hashlib
from constants import NOT_FOUND_STATUS_CODE


def validate_response(response, error_msg="An error occurred"):
    """
    Validate response
    Args:
        response (requests.Response): The response to validate
        error_msg (str): Default message to display on error

    Returns:
        True, if successful, TrendMicroDDANException otherwise
    """
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        if response.status_code == NOT_FOUND_STATUS_CODE:
            raise TrendMicroDDANNotFoundException(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

        raise TrendMicroDDANException(
            "{error_msg}: {error} {text}".format(
                error_msg=error_msg,
                error=error,
                text=error.response.content)
        )


def get_string_sha1(string):
    """
    Generate the SHA1 hash from string
    Args:
        string (str): string to use in hash

    Returns:
        (str) generated hash
    """
    hash_obj = hashlib.sha1(string.encode())
    return hash_obj.hexdigest()


def get_file_sha1(file_path):
    """
    Generate the SHA1 hash from file
    Args:
        file_path (str): file path

    Returns:
        (str) generated hash
    """
    if not os.path.exists(file_path):
        raise TrendMicroDDANException(f"File path \"{file_path}\" was not found")

    with open(file_path, "rb") as file:
        sha1 = hashlib.sha1(file.read()).hexdigest()

    return sha1


def get_opened_file(file_path):
    """
    Get opened file
    Args:
        file_path (str): file path

    Returns:
        (BufferedReader) opened file
    """
    if not os.path.exists(file_path):
        raise TrendMicroDDANException(f"File path \"{file_path}\" was not found")

    return open(file_path, "rb")


def validate_positive_integer(number, err_msg="Limit parameter should be positive"):
    if number <= 0:
        raise Exception(err_msg)
