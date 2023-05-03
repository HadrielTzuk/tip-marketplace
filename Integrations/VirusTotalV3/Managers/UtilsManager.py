import base64
import re
import tldextract
from SiemplifyDataModel import EntityTypes
from constants import EMAIL_REGEX, DOMAIN_REGEX, EMAIL_TYPE, DOMAIN_TYPE, IOC_TYPES, TIME_FORMAT
import os
import datetime

WHITELIST_FILTER = 1
BLACKLIST_FILTER = 2


def get_entity_original_identifier(entity):
    """
    helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get('OriginalIdentifier', entity.identifier)


def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def prepare_entity_for_manager(entity):
    if entity.entity_type == EntityTypes.URL:
        return encode_url(get_entity_original_identifier(entity))

    return get_entity_original_identifier(entity)


def get_entity_type(entity):
    """
    Helper function for getting entity type
    :param entity: entity from which function will get type
    :return: {str} entity type
    """
    if re.search(EMAIL_REGEX, get_entity_original_identifier(entity)) and entity.entity_type == EntityTypes.USER:
        return EMAIL_TYPE
    if re.search(DOMAIN_REGEX, get_entity_original_identifier(entity)) and entity.entity_type == EntityTypes.URL:
        return DOMAIN_TYPE

    return entity.entity_type


def get_domain_from_entity(identifier):
    """
    Extract domain from entity identifier
    :param identifier: {str} the identifier of the entity
    :return: {str} domain part from entity identifier
    """
    if "@" in identifier:
        return identifier.split("@", 1)[-1]
    try:
        result = tldextract.extract(identifier)
        if result.suffix:
            return ".".join([result.domain, result.suffix])
        return result.domain
    except ImportError:
        raise ImportError("tldextract is not installed. Use pip and install it.")

def save_attachment(path, name, content):
    """
    Save attachment to local path
    :param path: {str} Path of the folder, where files should be saved
    :param name: {str} File name to be saved
    :param content: {str} File content
    :return: {str} Path to the downloaded files
    """
    
    # Create path if not exists
    if not os.path.exists(path):
        raise Exception(f"Folder {path} not found.")
    # File local path
    local_path = os.path.join(path, name)
    with open(local_path, 'wb') as file:
        file.write(content.encode(encoding='UTF-8'))
        file.close()

    return local_path


def convert_days_to_milliseconds(days):
    """
    Convert days to milliseconds
    :param days: {int} days to convert
    :return: {int} converted milliseconds
    """
    return days * 24 * 60 * 60 * 1000


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


def prepare_ioc_for_manager(ioc, ioc_type):
    """
    Prepare ioc for manager
    :param ioc: {str} ioc
    :param ioc_type: {str} ioc type
    :return: {str} transformed ioc
    """
    if ioc_type == IOC_TYPES.get("url"):
        return encode_url(ioc)

    return ioc


def datetime_to_rfc3339(datetime_obj: datetime.datetime) -> str:
    """
    Convert datetime object to RFC 3999 representation
    :param datetime_obj: {datetime.datetime} The datetime object to convert
    :return: {str} The RFC 3999 representation of the datetime
    """
    return datetime_obj.strftime(TIME_FORMAT)


def pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, model, model_key, whitelist=None):
    # whitelist filter
    whitelist = whitelist or siemplify.whitelist
    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    model_value = getattr(model, model_key)
    model_values = model_value if isinstance(model_value, list) else [model_value]

    if whitelist:
        for value in model_values:
            if whitelist_filter_type == BLACKLIST_FILTER and value in whitelist:
                siemplify.LOGGER.info(f"'{value}' did not pass blacklist filter.")
                return False

            if whitelist_filter_type == WHITELIST_FILTER and value not in whitelist:
                siemplify.LOGGER.info(f"'{value}' did not pass whitelist filter.")
                return False

    return True
