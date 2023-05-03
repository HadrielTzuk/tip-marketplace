import os

from SiemplifyUtils import unix_now
from exceptions import JiraValidationError
from JiraConstants import FILTER_STRATEGY_MAPPING, FILTER_KEY_VALUES

UNIX_FORMAT = 1
DATETIME_FORMAT = 2
STORED_IDS_LIMIT = 1000
WHITELIST_FILTER = 1
BLACKLIST_FILTER = 2


def load_csv_to_list(csv, param_name) -> list:
    """
    Load comma separated values represented as string to a list
    :param csv: {str} of comma separated values with delimiter ','
    :param param_name: {str} the name of the variable we are validation
    :return: {list} of values
            raise JiraValidationError if failed to parse csv
    """
    try:
        if csv:
            return [t.strip() for t in csv.split(',') if t]
    except Exception:
        raise JiraValidationError(f"Failed to parse parameter {param_name}")


def get_file_path_extension(file_path: str) -> str:
    """
    Get extension of a filename
    :param file_path: {str} File path to get extension from
    :return: {str} File path extension
    """
    return os.path.splitext(file_path)[-1]


def is_empty_value(value):
    """
    Check whether a value is empty (keep 0 values)
    :param value: The value to check
    :return: True if value is empty, False otherwise
    """
    if not isinstance(value, str):
        return value is None

    return value.isspace() or value == "" or value == "None"


# Move to TIPCommon
def filter_old_alerts(logger, alerts, existing_ids, id_key='key'):
    """
    Filter alerts that were already processed
    :param logger: {SiemplifyLogger} Siemplify logger
    :param alerts: {list} The alerts to filter
    :param existing_ids: {list} The ids to filter
    :param id_key: {str} The key of identifier
    :return: {list} The filtered alerts
    """
    filtered_alerts = []
    for alert in alerts:
        id = getattr(alert, id_key)
        if id not in existing_ids:
            filtered_alerts.append(alert)
        else:
            if logger:
                logger.info('The alert {} skipped since it has been fetched before'.format(id))

    return filtered_alerts


# Move to TIPCommon
def is_approaching_timeout(python_process_timeout, connector_starting_time, timeout_threshold=0.9):
    """
    Check if a timeout is approaching.
    :param python_process_timeout: {int} The python process timeout
    :return: {bool} True if timeout is close, False otherwise
    """
    processing_time_ms = unix_now() - connector_starting_time
    return processing_time_ms > python_process_timeout * 1000 * timeout_threshold


# Move to TIPCommon
def pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, model, model_key):
    # whitelist filter
    whitelist = siemplify.whitelist if isinstance(siemplify.whitelist, list) else [siemplify.whitelist]
    whitelist_filter_type = BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    model_value = getattr(model, model_key)
    if whitelist:
        if whitelist_filter_type == BLACKLIST_FILTER and model_value in whitelist:
            siemplify.LOGGER.info(f"'{model_value}' did not pass blacklist filter.")
            return False

        if whitelist_filter_type == WHITELIST_FILTER and model_value not in whitelist:
            siemplify.LOGGER.info(f"'{model_value}' did not pass whitelist filter.")
            return False

    return True


def remove_empty_kwargs(**kwargs) -> dict:
    """
    Remove keys from dictionary that has the value None
    :param kwargs: key value arguments
    :return: {dict} dictionary without keys that have the value None
    """
    return {k: v for k, v in kwargs.items() if v is not None}


def bytes_to_megabytes(bytes: int):
    """
    Convert bytes to megabytes
    :param bytes: {int} Size in bytes
    :return: {float} Size in megabytes, 2 digits precision.
    """
    return round(bytes / 1024 / 1024, 2)


def filter_items(items, filter_key=None, filter_logic=None, filter_value=None, limit=None):
    """
    Filter list of items
    :param items: {list} list of items to filter
    :param filter_key: {str} filter key that should be used for filtering
    :param filter_logic: {str} filter logic that should be applied
    :param filter_value: {str} filter value that should be used for filtering
    :param limit: {int} limit for items
    """
    if FILTER_KEY_VALUES.get(filter_key) and FILTER_STRATEGY_MAPPING.get(filter_logic) and filter_value:
        items = [item for item in items
                 if FILTER_STRATEGY_MAPPING[filter_logic](getattr(item, FILTER_KEY_VALUES.get(filter_key)), filter_value)]

    return items[:limit] if limit else items
