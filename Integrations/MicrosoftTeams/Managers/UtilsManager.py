from SiemplifyUtils import unix_now
GLOBAL_TIMEOUT_THRESHOLD_IN_MIN = 1
TIMEOUT_THRESHOLD = 0.9


def is_approaching_timeout(python_process_timeout, connector_starting_time, timeout_threshold=TIMEOUT_THRESHOLD):
    """
    Check if a timeout is approaching.
    :param python_process_timeout: {int} The python process timeout
    :param connector_starting_time: {int} The connector start unix time
    :param timeout_threshold: {int} Determines which part of the execution time is available for execution
    :return: {bool} True if timeout is close, False otherwise
    """
    processing_time_ms = unix_now() - connector_starting_time
    return processing_time_ms > python_process_timeout * 1000 * timeout_threshold


def is_async_action_global_timeout_approaching(siemplify, start_time):
    return siemplify.execution_deadline_unix_time_ms - start_time < GLOBAL_TIMEOUT_THRESHOLD_IN_MIN * 60


def string_to_multi_value(string_value, delimiter=',', only_unique=False):
    """
    String to multi value.
    :param string_value: {str} String value to convert multi value.
    :param delimiter: {str} Delimiter to extract multi values from single value string.
    :param only_unique: {bool} include only unique values
    :return: {dict} fixed dictionary.
    """
    if not string_value:
        return []

    values = [single_value.strip() for single_value in string_value.split(delimiter) if single_value.strip()]
    if only_unique:
        seen = set()
        return [value for value in values if not (value in seen or seen.add(value))]

    return values

