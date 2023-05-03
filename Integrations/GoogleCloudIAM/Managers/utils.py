import json
from typing import List

from exceptions import GoogleCloudIAMValidationError


def load_csv_to_list(csv: str, param_name: str) -> List[str]:
    """
    Load comma separated values represented as string to a list. Remove duplicates if exist
    :param csv: {str} of comma separated values with delimiter ','
    :param param_name: {str} the name of the parameter we are loading csv to list
    :return: {[str]} List of separated string values
            raise GoogleCloudComputeValidationError if failed to parse csv string
    """
    try:
        return list(set([t.strip() for t in csv.split(',')]))
    except Exception:
        raise GoogleCloudIAMValidationError(f"Failed to load comma separated string parameter \"{param_name}\"")


def parse_string_to_dict(string):
    """
    Parse json string to dict
    :param string: string to parse
    :return: {dict} parsed dict
    """
    try:
        return json.loads(string)
    except Exception as err:
        raise GoogleCloudIAMValidationError(f"Unable to parse provided json. Error is: {err}")
