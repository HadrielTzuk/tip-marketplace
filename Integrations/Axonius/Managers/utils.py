import re
from typing import Dict, List

from consts import (
    VALID_EMAIL_REGEXP
)
from exceptions import (
    AxoniusValidationError
)


def remove_none_dictionary_values(**kwargs) -> Dict:
    """
    Remove None dictionary values
    :param kwargs: key value arguments
    :return: {dict} Dictionary with removed None values
    """
    return {k: v for k, v in kwargs.items() if v is not None}


def is_valid_email(user_name: str) -> bool:
    """
    Check if the user_name is valid email.
    :param user_name: {str} User name
    :return: {bool} True if valid email, else False
    """
    return bool(re.search(VALID_EMAIL_REGEXP, user_name))


def load_csv_to_list(csv: str, param_name: str) -> List[str]:
    """
    Load comma separated values represented as string to a list. Remove duplicates if exist
    :param csv: {str} of comma separated values with delimiter ','
    :param param_name: {str} the name of the parameter we are loading csv to list
    :return: {[str]} List of separated string values
            raise AxoniusValidationError if failed to parse csv string
    """
    try:
        return list(set([t.strip() for t in csv.split(',')]))
    except Exception:
        raise AxoniusValidationError(f"Failed to parse parameter \"{param_name}\"")
