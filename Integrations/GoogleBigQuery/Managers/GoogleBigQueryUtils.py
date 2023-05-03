import json

from GoogleBigQueryExceptions import GoogleBigQueryValidationError

def parse_string_to_dict(string):
    """
    Parse json string to dict
    :param string: string to parse
    :return: {dict} parsed dict
    """
    try:
        return json.loads(string)
    except Exception as err:
        raise GoogleBigQueryValidationError(f"Unable to parse provided json. Error is: {err}")
