import base64
import os
import pytz
from SiemplifyUtils import utc_now, convert_string_to_datetime, convert_timezone
from datetime import timedelta
from exceptions import ExchangeException
import urllib.parse


def get_time_filters(start_time_string, end_time_string, minutes_backwards):
    """
    Get start and end datetime
    :param start_time_string: {str} Start time string
    :param end_time_string: {str} End time string
    :param minutes_backwards: {int} Time backwards in minutes
    :return: {tuple} start and end datetime
    """
    start_time, end_time = None, None

    if start_time_string:
        start_time = convert_string_to_utc_datetime(start_time_string)
        end_time = convert_string_to_utc_datetime(end_time_string) if end_time_string else None
    elif minutes_backwards:
        start_time = utc_now().replace(tzinfo=pytz.utc) - timedelta(minutes=int(minutes_backwards))

    if start_time and end_time and start_time > end_time:
        raise Exception("End Time should be later than Start Time")

    return start_time, end_time


def convert_string_to_utc_datetime(datetime_string):
    """
    Convert datetime string to utc datetime object
    :param datetime_string: {str} Datetime string
    :return: {Datetime} Datetime object
    """
    return convert_timezone(convert_string_to_datetime(datetime_string), "UTC").replace(tzinfo=pytz.utc)


def is_invalid_prefix(prefix):
    """
    Validate prefix string
    :param prefix: {str} Prefix to validate
    :return: {bool} True if invalid, False otherwise
    """
    return " " in prefix


def transform_dict_keys(original_dict, prefix, suffix, keys_to_except=[]):
    """
    Transform dict keys by adding prefix and suffix
    :param original_dict: {dict} Dict to transform keys
    :param prefix: {str} Prefix for the keys
    :param suffix: {str} Suffix for the keys
    :param keys_to_except: {list} The list of keys which shouldn't be transformed
    :return: {dict} The transformed dict
    """
    if prefix and suffix:
        return {f"{prefix}_{key}_{suffix}" if key not in keys_to_except else key: value
                for key, value in original_dict.items()}
    elif prefix:
        return {f"{prefix}_{key}" if key not in keys_to_except else key: value for key, value in original_dict.items()}

    return original_dict


def save_file(file_content, file_path):
    """
    Decode file content and save as file
    :param file_content: {str} File base64 content
    :param file_path: {str} File path
    :return: {str} File path
    """
    try:
        file_content = base64.b64decode(file_content).decode()
        with open(file_path, 'w') as f:
            f.write(file_content)
            f.close()
        return file_path
    except Exception as e:
        raise ExchangeException('File Error: {}'.format(e))


def delete_files(siemplify_logger, file_paths):
    """
    Delete files
    :param siemplify_logger: Siemplify logger
    :param file_paths: {list} List of file paths to delete
    :return: {void}
    """
    for file_path in file_paths:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                siemplify_logger.error("Unable to delete file {}.".format(file_path))
                siemplify_logger.exception(e)


def convert_comma_separated_to_list(comma_separated):
    """
    Convert comma-separated string to list
    :param comma_separated: String with comma-separated values
    :return: List of values
    """
    return [item.strip() for item in comma_separated.split(',')] if comma_separated else []


def decode_url(url):
    """
    Decode encoded url
    :param url: {str} encoded url
    :return: {str} decoded url
    """
    return urllib.parse.unquote_plus(url)
