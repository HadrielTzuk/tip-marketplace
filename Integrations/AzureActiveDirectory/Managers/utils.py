import re
from constants import FILTER_LOGIC_EQUALS, FILTER_LOGIC_CONTAINS

VALID_EMAIL_REGEXP = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


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


def filter_items(items, filter_key=None, filter_value=None, filter_logic=None, limit=None):
    """
    Filter list of items
    :param items: {list} list of items to filter
    :param filter_key: {str} filter key that should be used for filtering
    :param filter_value: {str} filter value that should be used for filtering
    :param filter_logic: {str} filter logic that should be applied
    :param limit: {int} limit for items
    """
    if filter_key and filter_value:
        if filter_logic == FILTER_LOGIC_EQUALS:
            items = [item for item in items if getattr(item, filter_key) == filter_value]

        if filter_logic == FILTER_LOGIC_CONTAINS:
            items = [item for item in items if filter_value in (getattr(item, filter_key, "") or "")]

    return items[:limit] if limit else items


def is_valid_email(user_name):
    """
    Check if the user_name is valid email.
    :param user_name: {str} User name
    :return: {bool} True if valid email, else False
    """
    return bool(re.search(VALID_EMAIL_REGEXP, user_name))
