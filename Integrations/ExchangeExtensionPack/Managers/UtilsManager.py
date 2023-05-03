import re
from constants import POWERSHALL_COMMAND, ERROR_TEXTS, RESULT_FILE_NAME, EMAIL_REGEX, DOMAIN_REGEX
from ExchangeExtensionPackExceptions import ExchangeExtensionPackPowershellException, \
    ExchangeExtensionPackGssntlmsspException, ExchangeExtensionPackNoResults, ExchangeExtensionPackNotFound, \
    ExchangeExtensionPackAlreadyExist, ExchangeExtensionPackSessionError, ExchangeExtensionPackInvalidQuery
import os
import json
from ScriptResult import EXECUTION_STATE_INPROGRESS


NETWORK_FAIL_COUNT_KEY = "current_network_fails_count"


def validate_error(error):
    error_message = str(error)

    if ERROR_TEXTS.get("powershell") in error_message:
        raise ExchangeExtensionPackPowershellException(error)

    if ERROR_TEXTS.get("gss_failure") in error_message:
        raise ExchangeExtensionPackGssntlmsspException(error)

    if ERROR_TEXTS.get("no_results") in error_message:
        raise ExchangeExtensionPackNoResults(error)

    if any(text in error_message for text in ERROR_TEXTS.get("not_found")):
        raise ExchangeExtensionPackNotFound(error)

    if ERROR_TEXTS.get("already_exists") in error_message:
        raise ExchangeExtensionPackAlreadyExist(error)

    if ERROR_TEXTS.get("session_error") in error_message:
        raise ExchangeExtensionPackSessionError(error)

    if ERROR_TEXTS.get("invalid_query") in error_message:
        raise ExchangeExtensionPackInvalidQuery(error)

    raise Exception(error)


def read_file_content(siemplify_logger, file_name=RESULT_FILE_NAME, default_value={}):
    """
    Read file content
    :param siemplify_logger: Siemplify logger
    :param file_name: {str} The name of the file
    :param default_value: The default value in case of the empty file content
    :return: The file content
    """
    if not os.path.exists(file_name):
        return default_value

    try:
        with open(file_name, "r") as f:
            content = f.read()
            return json.loads(content) if content and content != "None" else default_value
    except Exception as e:
        siemplify_logger.error("Unable to read file: {}".format(e))
        siemplify_logger.exception(e)
        return default_value


def delete_file(siemplify_logger, file_name=RESULT_FILE_NAME):
    """
    Delete file
    :param siemplify_logger: Siemplify logger
    :param file_name: {str} The name of the file
    :return: {void}
    """
    if os.path.exists(file_name):
        try:
            os.remove(file_name)
        except Exception as e:
            siemplify_logger.error("Unable to delete file: {}".format(e))
            siemplify_logger.exception(e)


def validate_email_address(email_address):
    return re.match(EMAIL_REGEX, email_address, re.IGNORECASE | re.UNICODE)


def validate_domain(domain):
    return re.match(DOMAIN_REGEX, domain, re.IGNORECASE | re.UNICODE)


def prevent_async_action_fail_in_case_of_network_error(e, additional_data_json, max_retry, output_message,
                                                       result_value, status):
    # this is the list of error messages, which we will skip until that error will be fixed, or async action
    # will time out.
    to_skip_errors = []

    for to_skip_error in to_skip_errors:
        if to_skip_error in str(e):
            max_retry = None

    # this is the list of error messages, where we will try to run async action another {max_retry} times
    # before raising
    prevent_errors_to_fail = [
        "Cannot validate argument on parameter 'Session'",
        "MI_RESULT_FAILED",
        "timed out after",
        "MaxConcurrency"
    ]

    for error in prevent_errors_to_fail + to_skip_errors:
        if error not in str(e):
            continue

        additional_data = json.loads(additional_data_json)

        try:
            current_network_fails_count = additional_data.get(NETWORK_FAIL_COUNT_KEY, 0) if additional_data else 0
        except Exception as e:
            current_network_fails_count = 0

        if not max_retry or (current_network_fails_count < max_retry):
            status = EXECUTION_STATE_INPROGRESS
            output_message = "Something went wrong. Retrying..."

            if max_retry:
                output_message = "{} ({}/{})".format(output_message, current_network_fails_count, max_retry)

            if not isinstance(additional_data, dict):
                additional_data = {"main_result": additional_data}

            additional_data[NETWORK_FAIL_COUNT_KEY] = current_network_fails_count + 1
            result_value = json.dumps(additional_data)
        else:
            output_message = "Reached allowed maximum ({}) retry attempts: {}".format(max_retry, output_message)

        break

    return output_message, result_value, status
