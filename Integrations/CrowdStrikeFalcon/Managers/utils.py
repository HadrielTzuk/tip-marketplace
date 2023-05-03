import datetime
import os
from datetime import datetime, timezone, timedelta

import requests

from SiemplifyUtils import unix_now
from TIPCommon import get_last_success_time, read_content, write_content
from constants import (
    OFFSET_FILE,
    OFFSET_DB_KEY,
    KEY_FOR_SAVED_OFFSET,
    PLACEHOLDER_START,
    PLACEHOLDER_END
)
from datetime import datetime

HASH_TYPES_WITH_LEN_MAPPING = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}

UNIX_FORMAT = 1
DATETIME_FORMAT = 2
STORED_IDS_LIMIT = 1000
TIMEOUT_THRESHOLD = 0.9


def timestamp_to_iso(timestamp):
    """
    Function that changes the timestamp to a human-readable format
    :param timestamp: {int} Unix Timestamp
    :return: {str} Timestamp in human readable form
    """
    return datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).isoformat(
        " ", "seconds"
    )


# Move to TIPCommon
def is_approaching_timeout(
    python_process_timeout, connector_starting_time, timeout_threshold=0.9
):
    """
    Check if a timeout is approaching.
    :param python_process_timeout: {int} The python process timeout
    :param connector_starting_time: {int} The connector start unix time
    :param timeout_threshold: {int} Determines which part of the execution time is available for execution
    :return: {bool} True if timeout is close, False otherwise
    """
    processing_time_ms = unix_now() - connector_starting_time
    return processing_time_ms > python_process_timeout * 1000 * timeout_threshold


def get_formatted_last_success_time(
    siemplify,
    offset_with_metric,
    time_format=DATETIME_FORMAT,
    print_value=True,
    date_time_format=None,
):

    raw_datetime = get_last_success_time(
        siemplify, offset_with_metric, time_format=time_format, print_value=print_value
    )
    return (
        raw_datetime
        if not date_time_format
        else raw_datetime.strftime(date_time_format)
    )

def convert_unix_time_to_datetime(unix_time):
    """
    The method is used to convert unix time to date
    Args:
        unix_time (int): Unix Time
    """
    return datetime.fromtimestamp(unix_time / 1000).strftime("%Y-%m-%dT%H:%M:%S")

def validate_response(response, error_msg="An error occurred"):
    """
    Validate response
    :param response: {requests.Response} The response to validate
    :param error_msg: {unicode} Default message to display on error
    """
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        raise Exception(
            "{error_msg}: {error} {text}".format(
                error_msg=error_msg, error=error, text=error.response.content
            )
        )

    return True


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get("OriginalIdentifier", entity.identifier)


def get_existing_list(dictionary, key):
    """
    Get existing list
    :param dictionary: {dict} dictionary
    :param key: {str} key from dict
    :return: {str} dictionary
    """
    if not dictionary.get(key):
        dictionary[key] = []

    return dictionary[key]


def get_hash_type(hash_value):
    """
    determine the hash type
    :param hash_value: {str} hash value
    :return: {str} hash type
    """
    return HASH_TYPES_WITH_LEN_MAPPING.get(len(hash_value))


def get_domain_from_entity(identifier):
    """
    Extract domain from entity identifier
    :param identifier: {str} the identifier of the entity
    :return: {str} domain part from entity identifier
    """
    if "@" in identifier:
        return identifier.split("@", 1)[-1]
    try:
        import tldextract

        result = tldextract.extract(identifier)
        join_with = "."
        if result.suffix:
            if result.subdomain:
                return join_with.join([result.subdomain, result.domain, result.suffix])

            return join_with.join([result.domain, result.suffix])

        elif result.subdomain:
            return join_with.join([result.subdomain, result.domain])

        return result.domain

    except ImportError:
        raise ImportError("tldextract is not installed. Use pip and install it.")


def get_offset(siemplify, default_value=0):
    """
    Get last saved offset from file
    @param siemplify: Siemplify Object
    @param default_value: (optional) {int} default value to return if function failed
    @return: {int} Offset of the detection
    """
    offset = read_content(
        siemplify, OFFSET_FILE, OFFSET_DB_KEY, {KEY_FOR_SAVED_OFFSET: default_value}
    ).get(KEY_FOR_SAVED_OFFSET)
    return offset


def store_offset(siemplify, offset):
    """
    Store given offset in file with given path
    @param siemplify: Siemplify Object
    @param offset: {int} Offset of the detection
    """
    write_content(siemplify, {KEY_FOR_SAVED_OFFSET: offset}, OFFSET_FILE, OFFSET_DB_KEY)


ASYNC_ACTION_TIMEOUT_THRESHOLD_MS = 35000


def is_action_approaching_timeout(action_start_time, python_process_timeout):
    """
    Check if a timeout is approaching.
    :param action_start_time: {int} Action start time
    :param python_process_timeout: {int} The python process timeout
    :return: {bool} True if timeout is close, False otherwise
    """
    return (
        action_start_time >= python_process_timeout - ASYNC_ACTION_TIMEOUT_THRESHOLD_MS
    )


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
        os.makedirs(path)
    # File local path
    local_path = os.path.join(path, name)
    with open(local_path, "wb") as file:
        file.write(content)
        file.close()

    return local_path


def calculate_date(days):
    """
    Calculate date by adding provided days amount to utc now
    :param days: {int} amount of days
    :return: {str} calculated date in '%Y-%m-%dT%H:%M:%SZ' format
    """
    utc_now = datetime.utcnow()
    calculated_date = utc_now + timedelta(days=days)
    return calculated_date.strftime("%Y-%m-%dT%H:%M:%SZ")


def convert_list_to_comma_string(values_list):
    """
    Convert list to comma-separated string
    :param values_list: List of values
    :return: String with comma-separated values
    """
    return (
        ", ".join(str(v) for v in values_list)
        if values_list and isinstance(values_list, list)
        else values_list
    )


def convert_comma_separated_to_list(comma_separated):
    """
    Convert comma-separated string to list
    :param comma_separated: String with comma-separated values
    :return: List of values
    """
    return (
        [item.strip() for item in comma_separated.split(",")] if comma_separated else []
    )


def format_template(template: str, data: dict) -> str:
    """
    Transform string containing template using provided data

    Args:
        template: String containing template
        data: Data to use for formatting

    Returns:
        Formatted template
    """
    placeholder = ""
    placeholder_nesting_count = 0
    nesting_decreased = False
    for char in template:
        if char == " " and nesting_decreased:
            # closing bracket case
            nesting_decreased = False
            template = replace_placeholder(data, placeholder, template)
            placeholder = ""
            placeholder_nesting_count = 0

        if char == PLACEHOLDER_START:
            placeholder_nesting_count += 1

        if placeholder_nesting_count > 0:
            placeholder += char

        if char == PLACEHOLDER_END:
            if placeholder_nesting_count > 0:
                placeholder_nesting_count -= 1
            nesting_decreased = True
        if placeholder_nesting_count == 0 and placeholder:
            nesting_decreased = False
            template = replace_placeholder(data, placeholder, template)
            placeholder = ""
    return template


def replace_placeholder(data: dict, placeholder: str, template: str) -> str:
    """
    Replaces first template placeholder with given data

    Args:
        data: Dictionary with placeholder values
        placeholder: Part of template that should be replaced
        template: String with square brackets (placeholders)

    Returns:
        Template with replaced placeholders
    """
    data_key = placeholder[1:-1]
    data_value = data.get(data_key)
    if data_value:
        return template.replace(placeholder, data_value, 1)
    return template.replace(placeholder, "", 1)

def convert_hours_to_milliseconds(hours):
    """
    Convert hours to milliseconds
    Args:
        hours: {int} hours to convert
    :return: {int} converted milliseconds
    """
    return hours * 60 * 60 * 1000
