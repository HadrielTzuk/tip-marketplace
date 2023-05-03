# =====================================
#              IMPORTS                #
# =====================================
import copy
from typing import List

# =====================================
#             CONSTANTS               #
# =====================================
DEFAULT_REGEX_MAP = {"subject": r"(?i)(?:Subject: )?(?:(?:re|fwd):\ )*(.*)$",
                     "from_list": r"(?<=From:).*<(.*?)>|(?<=From: ).*",
                     "to": r"(?<=To:).*<(.*?)>|(?<=^To: ).*"}
# TODO: This regex also fetches domains from email and i don't know how to exclude it (without ^ at the start)
#  because it can be in the middle of the sentence. Also think how to exclude domain if proto is wrong. It is fetching
#  without wrong proto but valid url after is fetched.
#  Workaround: I decided to remove email in python (string contains @)
#  ATTENTION: It can remove the whole valid domain with email in params
URLS_REGEX = r"(?i)(?:(?:(?:http|https)(?:://))|www\.(?!://))(?:[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,=%])+"
IMG_REGEX = r'<img[^>]* src=\"([^\"]*)\"[^>]*>'
# Move to TIPCommon
STORED_IDS_LIMIT = 3000


def safe_str_cast(data, default_value=None, current_encoding='utf-8', target_encoding='utf-8', convert_none=False):
    """
    :param data: {Input} Cam be string, unicode or object.
    :param default_value: {str} Default value return on error.
    :param current_encoding: {str} Current value encoding - Relevant for STR data.
    :param target_encoding: {str} Target
    :param convert_none: {bool}
    :return:
    """
    try:
        if not convert_none and data is None:
            return None
        elif isinstance(data, str):
            return data.encode(target_encoding)
        elif isinstance(data, str):
            return data.decode(current_encoding).encode(target_encoding)
        else:
            return str(data).encode(target_encoding)
    except:
        if default_value:
            return default_value
        raise Exception("Failed casting received data to string.")


def build_json_result_from_emails_list(emails_list):
    """
    Converts list of tuples (folder_name, EmailModel()) into a JSON suitable for JSON output by activity
    :param emails_list: {list} List of tuples (folder_name, EmailModel())
    :return: {dict} Dict containing contents of emails list
    """
    json_results = {"emails": []}

    for _, email in emails_list:
        json_results["emails"].append(email.to_dict())

    return json_results


def save_attachments_to_case(siemplify, attachments):
    """
    Allows to save attachments to the case by passing a dict of email attachments
    :param siemplify: {SiemplifyAction} Current SiemplifyAction
    :param attachments: {dict} Dict with attachments absolute paths grouped by email_uids: {"email_uid_1": ["<path_to_file_1>, <path_to_file_2>"], "email_uid_1": ["<path_to_file_1>, <path_to_file_2>"]}
    :return: {tuple} Number of emails with attachments and total number of files
    """
    num_emails = num_files = 0
    for email_id, attachments_list in list(attachments.items()):
        if attachments_list:
            num_emails += 1
        for attach in attachments_list:
            try:
                siemplify.add_attachment(attach)
                num_files += 1
            except Exception as e:
                siemplify.LOGGER.error("Unable to save attachment {0} from email {1} to the case".format(attach, email_id))
                siemplify.LOGGER.exception(e)
    return num_emails, num_files


def build_regex_map(regex_list):
    """
    Converts whitelist into a regex map
    :param regex_list: {list} List of unicode strings, representing regex expressions to extract specific fields from email body using format "<attribute_name>: <regex expression to extract it>"
    :return: {dict} Regex map, where keys are unicode field names and values - are regex expressions to extract them
    """
    regex_map = copy.deepcopy(DEFAULT_REGEX_MAP)
    for regex_item in regex_list:
        try:
            if ': ' in regex_item:
                # Split only once by ':'
                user_regex = regex_item.split(': ', 1)
                # check if user regex include key (regex name) and value (the regex itself)
                if len(user_regex) >= 2:
                    regex_map.update({"regex_{}".format(user_regex[0]): user_regex[1]})
        except Exception as e:
            self.logger.error(
                "Unable to parse regex list item {}. Ignoring item and continuing.".format(
                    regex_item))
            self.logger.exception(e)
    return regex_map


def load_attachments_to_dict(siemplify_logger, attachment_paths: List[str]) -> dict:
    """
    Load local specified attachments
    :param siemplify_logger: Siemplify logger instance
    :param attachment_paths: {[str]} List of attachment paths in local disk
    :return: {dict} Dictionary of successfully loaded attachments. Key is local file path, value is binary content of the file
    """
    attachments_dict = {}
    siemplify_logger.info("Reading attachments from disk")
    for attachment_path in attachment_paths:
        try:
            with open(attachment_path, "rb") as f:
                attachments_dict[attachment_path] = f.read()
        except Exception as e:
            siemplify_logger.error("Unable to read attachment {} from disk".format(attachment_path))
            siemplify_logger.exception(e)
    return attachments_dict


def is_invalid_prefix(prefix):
    """
    Validate prefix string
    :param prefix: {str} Prefix to validate
    :return: {bool} True if invalid, False otherwise
    """
    return " " in prefix


def transform_dict_keys(original_dict, prefix, suffix=None, keys_to_except=None):
    """
    Transform dict keys by adding prefix and suffix
    :param original_dict: {dict} Dict to transform keys
    :param prefix: {str} Prefix for the keys
    :param suffix: {str} Suffix for the keys
    :param keys_to_except: {list} The list of keys which shouldn't be transformed
    :return: {dict} The transformed dict
    """
    keys_to_except = keys_to_except if keys_to_except else []
    if prefix and suffix:
        return {f"{prefix}_{key}_{suffix}" if key not in keys_to_except else key: value
                for key, value in original_dict.items()}
    elif prefix:
        return {f"{prefix}_{key}" if key not in keys_to_except else key: value for key, value in original_dict.items()}

    return original_dict


class BaseEmailError(Exception):
    """
    Base Email Connector Exception
    """
    pass


class EmailAttributeError(BaseEmailError):
    pass


class EmailDataModelTransformationError(BaseEmailError):
    pass


class InvalidParameterError(BaseEmailError):
    """
    Exception in case of invalid parameter
    """
    pass
