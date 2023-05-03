from string import digits, ascii_letters

from consts import VALID_CHARACTERS
from exceptions import AWSIAMValidationException


def load_csv_to_list(csv, param_name):
    """
    Load comma separated values represented as string to a list
    :param csv: {str} of comma separated values with delimiter ','
    :param param_name: {str} the name of the variable we are validation
    :return: {list} of values
            raise AWSIAMValidationException if failed to parse csv
    """
    try:
        return [t.strip() for t in csv.split(',')]
    except Exception:
        raise AWSIAMValidationException(f"Failed to parse parameter {param_name}")


def is_name_valid(name):
    """
    Check if name contain only alphanumeric characters and/or the following: +=.@_-.
    :param name: {str} The name to check is validation
    :return: True if name do not contains any invalid characters, False otherwise.
    """
    if set(name).difference(ascii_letters + digits + VALID_CHARACTERS):
        return False
    return True


def remove_empty_kwargs(**kwargs) -> dict:
    """
    Remove keys from dictionary that has the value None
    :param kwargs: key value arguments
    :return: {dict} dictionary without keys that have the value None
    """
    return {k: v for k, v in kwargs.items() if v is not None}
