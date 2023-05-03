# IMPORTS
import json
import re
from exchangelib import EWSTimeZone, FileAttachment
import os
import copy
from urllib.parse import urlparse
import hashlib
from emaildata.metadata import MetaData
from exchangelib import Message
from exchangelib.items import MeetingRequest, MeetingCancellation, MeetingResponse
from ExchangeManager import SiemplifyMessageDictKeys
from EmailUtils import get_unicode_str, check_url_enclosing
from ScriptResult import EXECUTION_STATE_INPROGRESS
from constants import DEFAULT_LIST_DELIMITER, DEFAULT_URLS_LIST_DELIMITER, URLS_REGEX
from TIPCommon import validate_timestamp


# CONSTS
FWD_KEYS = ('fwd:', 'fw:')
DEFAULT_SUBJECT_TEXT = "Message Has No Subject"

DEFAULT_REGEX_MAP = {
    "urls": URLS_REGEX,
    "subject": r"(?<=Subject: ).*",
    "from_list": r"(?<=From: ).*",
    "to": r"(?m)(?<=^To: ).*"
}

ATTACHMENTS_EXTENSION = '.unsafe'
FILE_NAME_EVENT_FIELD_PATTERN = "file_name_{0}"
FILE_MD5_EVENT_FIELD_PATTERN = "file_md5_{0}"
URL_EVENT_FIELD_PATTERN = "urls_{0}"
NETWORK_FAIL_COUNT_KEY = 'current_network_fails_count'


class ExchangeCommon(object):
    def __init__(self, logger, exchange_manager):
        self.logger = logger
        self.exchange_manager = exchange_manager

    @staticmethod
    def validate_max_days_backwards(datetime_timestamp, max_days_backwards):
        timestamp = validate_timestamp(datetime_timestamp, max_days_backwards, offset_is_in_days=True)

        # Change tzinfo to be EWSTimeZone timezone object
        return timestamp.replace(tzinfo=EWSTimeZone.timezone('UTC'))

    @staticmethod
    def set_proxy(proxy_server_address, proxy_username=None, proxy_password=None):
        """
        Configure proxy
        :param proxy_server_address: {str} The proxy server address
        :param proxy_username: {str} Proxy username
        :param proxy_password: {str} Proxy password
        """
        server_url = urlparse(proxy_server_address)

        scheme = server_url.scheme
        hostname = server_url.hostname
        port = server_url.port

        credentials = ""
        if proxy_username and proxy_password:
            credentials = "{0}:{1}@".format(proxy_username, proxy_password)

        proxy_str = "{0}://{1}{2}".format(scheme, credentials, hostname)

        if port:
            proxy_str += ":{0}".format(str(port))

        os.environ['http_proxy'] = proxy_str  # http://<user>:<pass>@<proxy>:<port>
        os.environ['https_proxy'] = proxy_str  # https://<user>:<pass>@<proxy>:<port>
        os.environ['proxy'] = "on"

    def handle_fwd(self, message, event_details, exchange_manager):
        """
        handle forwarded mail - extract the original to&from fields
        using two separated functions cause the eml object is different from exchangelib Message object
        :param message: exchangelib Message object OR eml message which is raw message object
        :param event_details: {dict} event details
        :param exchange_manager: {ExchangeManager instance}
        :return: {dict} modified event details
        """
        if isinstance(message, Message) or\
                isinstance(message, MeetingRequest) or\
                isinstance(message, MeetingResponse) or\
                isinstance(message, MeetingCancellation):
            # this is exchangelib Message object
            return self.handle_fwd_exchange_msg(message, event_details, exchange_manager)
        else:
            # this is email raw message object
            message = MetaData(message).to_dict()
            return self.handle_fwd_eml(message, event_details)

    @staticmethod
    def handle_fwd_eml(message, event_details):
        """
        handle forwarded mail - extract the original to&from fields
        specific function for eml object (raw message object)
        :param event_details: {dict} event details
        :param message: eml message which is raw message object
        :return: {dict} modified event details
        """
        is_fwd = True if message.get('subject') and message['subject'].lower().startswith(FWD_KEYS) else False

        # In case of an regular email - not a forwarded email
        # This will override all same regex keys in event_details, for mapping and modeling
        if not is_fwd:
            event_details['subject'] = message.get('subject') or DEFAULT_SUBJECT_TEXT
            event_details['from'] = message.get('sender', '')
            event_details['to'] = ";".join(message.get('to')) if len(message.get('to')) else ''
        else:
            # fwd email
            # add original info
            event_details['from'] = event_details['from_list'].split(DEFAULT_LIST_DELIMITER)[-1] if event_details.get(
                'from_list') else ''
            event_details['to'] = event_details['to'].split(DEFAULT_LIST_DELIMITER)[-1] if event_details.get(
                'to') else ''
            event_details['subject'] = event_details['subject'].split(DEFAULT_LIST_DELIMITER)[0] if event_details.get(
                'subject') else DEFAULT_SUBJECT_TEXT

            # add latest info
            event_details['last_email_sender'] = message.get('sender', '')
            event_details['last_email_recipient'] = ";".join(message.get('to')) if len(message.get('to')) else ''

        return event_details

    @staticmethod
    def handle_fwd_exchange_msg(msg, event_details, exchange_manager):
        """
        handle forwarded mail - extract the original to&from fields
        specific function for exchangelib message object
        :param msg: exchangelib Message object
        :param event_details: {dict} event details
        :param exchange_manager: {ExchangeManager instance}
        :return: {dict} modified event details
        """
        is_fwd = True if msg.subject and msg.subject.lower().startswith(FWD_KEYS) else False

        # In case of a not forwarded message
        if not is_fwd:
            event_details['subject'] = msg.subject or DEFAULT_SUBJECT_TEXT
            event_details['from'] = msg.author.email_address or ''
            event_details['to'] = exchange_manager.account.primary_smtp_address or ''
        else:
            # In case of forwarded:
            # add original
            event_details['from'] = event_details['from_list'].split(DEFAULT_LIST_DELIMITER)[0] if event_details.get(
                'from_list') else msg.author.email_address
            event_details['to'] = event_details['to'].split(DEFAULT_LIST_DELIMITER)[-1] if event_details.get('to') else ''
            event_details['subject'] = event_details['subject'].split(DEFAULT_LIST_DELIMITER)[0] if event_details.get(
                'subject') else DEFAULT_SUBJECT_TEXT

            # add latest info
            event_details['last_email_sender'] = msg.author.email_address or ''
            event_details['last_email_recipient'] = exchange_manager.account.primary_smtp_address or ''

        return event_details

    @staticmethod
    def extract_regex_from_content(content, regex_map):
        """
        Get urls, subject, from and to addresses from email body
        :param content: {str} email body
        :param regex_map: {dict} regex map
        :return: {dict} fields after parse.
        """
        result_dictionary = {}

        for key, regex_value in regex_map.items():
            regex_object = re.compile(regex_value)
            all_results = regex_object.findall(content)
            # check if in default regex - NOT Divide keys
            if key in DEFAULT_REGEX_MAP.keys():
                if all_results:
                    if key == "urls":
                        all_results = [check_url_enclosing(result) for result in all_results]
                        result_dictionary[key] = DEFAULT_URLS_LIST_DELIMITER.join(all_results)
                    else:
                        result_dictionary[key] = DEFAULT_LIST_DELIMITER.join(all_results)
            else:
                for index, result in enumerate(all_results, 1):
                    # Divide keys
                    key_name = '{0}_{1}'.format(key, index) if len(
                        all_results) > 1 else key
                    result_dictionary[key_name] = get_unicode_str(result)

        return result_dictionary

    def is_matching_exclude_patterns(self, message, subject_exclude_pattern=None, body_exclude_pattern=None):
        """
        Get first message content from list which is not matching patterns.
        :param message: {dict} Siemplify message object.
        :param subject_exclude_pattern: {str} Regex pattern, which would exclude emails with matching subject.
        :param body_exclude_pattern: {str} Regex pattern, which would exclude emails with matching body.
        :return: {bool} Relevant reply: True if matches one of the exclude patterns; False - otherwise.
        """
        body_parts = [message.get('text_body'), message.get('unique_body')]

        if body_exclude_pattern:
            for part in body_parts:
                if part and re.findall(body_exclude_pattern, part):
                    return True

        if subject_exclude_pattern:
            if message.get('subject') and re.findall(subject_exclude_pattern, message.get('subject')):
                return True

        return False

    @staticmethod
    def extract_content(msg):
        """
        Extracts content from an e-mail message.
        :param msg: {email.message.Message} An eml object
        :return: {tuple} Text body, Html body, files dict (file_name: file_hash),
        count of parts of the emails
        """
        html_body = ""
        text_body = ""
        files = {}
        count = 0

        if not msg.is_multipart():
            if msg.get_filename():  # It's an attachment
                fn = msg.get_filename()
                files[fn] = str(hashlib.md5(msg.get_payload(decode=True)).hexdigest())
                return text_body, html_body, files, 1

            # Not an attachment!
            # See where this belong - text_body or html_body
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                text_body += msg.get_payload(decode=True)
            elif content_type == "text/html":
                html_body += msg.get_payload(decode=True)

            return text_body, html_body, files, 1

        # This IS a multipart message.
        # So, we iterate over it and call extract_content() recursively for
        # each part.
        for part_msg in msg.get_payload():
            # part is a new Message object which goes back to extract_content
            part_text_body, part_html_body, part_files, part_count = ExchangeCommon.extract_content(
                part_msg)
            text_body += part_text_body
            html_body += part_html_body
            files.update(part_files)
            count += part_count

        return text_body, html_body, files, count

    def get_user_first_valid_message(self, sender, messages, subject_exclude_pattern=None, body_exclude_pattern=None):
        """
        Get all messages sent by recipient.
        :param sender: {string} sender address.
        :param messages: {list} list of message dicts.
        :param subject_exclude_pattern: {string} subject regex exclude pattern.
        :param body_exclude_pattern: {string} subject regex exclude pattern.
        :return: {list} list of relevant message dicts.
        """
        if not messages:
            return None

        senders_messages = [message for message in messages if message[
            SiemplifyMessageDictKeys.AUTHOR_KEY].lower() == sender.lower()]

        self.logger.info("Found {0} messages for sender {1}".format(len(senders_messages), sender))

        try:
            senders_messages = sorted(senders_messages, key=lambda i: i[
                SiemplifyMessageDictKeys.CREATED_TIME_KEY])
        except Exception as err:
            self.logger.error("Failed sorting messages for sender {0} by time.".format(sender))
            self.logger.exception(err)

        for sequence, message in enumerate(senders_messages):
            self.logger.info(
                'Checking message match exclude pattern for sender: {0}, message sequence:{1}'.format(sender, sequence + 1))
            is_message_matching_exclude_patterns = self.is_matching_exclude_patterns(message, subject_exclude_pattern,
                                                                                     body_exclude_pattern)

            if not is_message_matching_exclude_patterns:
                self.logger.info("Message in sequence {0} for sender {1} is valid.".format(sequence + 1, sender))
                return message
            self.logger.info("Message in sequence {0} for sender {1} is not valid.".format(sequence + 1, sender))

    def build_regex_map(self, regex_list, default_regex_map=None):
        regex_map = copy.deepcopy(default_regex_map or DEFAULT_REGEX_MAP)
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
                    "Unable to get parse whitelist item {}. Ignoring item and continuing.".format(
                        regex_item))
                self.logger.exception(e)
        return regex_map

    @staticmethod
    def prevent_async_action_fail_in_case_of_network_error(e, additional_data_json, max_retry, output_message,
                                                           result_value, status):
        # this is the list of error messages, which we will skip until that error will be fixed, or async action will
        # time out.
        to_skip_errors = ['The server cannot service this request right now']
        for to_skip_error in to_skip_errors:
            if to_skip_error in str(e):
                max_retry = None

        # this is the list of error messages, where we will try to run async action another {max_retry} times
        # before raising
        prevent_errors_to_fail = [
            'HTTPSConnectionPool',
            'HTTPConnectionPool',
            'Read timed out',
            'Connection aborted',
            'Connection broken',
            'ConnectionResetError',
            'ErrorMessageTransientError',
            'Unknown ResponseCode',
            'closed the transport stream',
            'The server is too busy to process the request',
            'Try again later',
            'Could not connect to server',
            'The mailbox database is temporarily unavailable',
            'No valid protocols in response',
            'The specified object was not found in the store',
            'Unknown failure',
            'Unknown error',
            'failed with timeout',
            'Name or service not known',
        ]
        for error in prevent_errors_to_fail+to_skip_errors:
            if error not in str(e):
                continue
            additional_data = json.loads(additional_data_json)
            try:
                current_network_fails_count = additional_data.get(NETWORK_FAIL_COUNT_KEY, 0) if additional_data else 0
            except Exception as e:
                current_network_fails_count = 0

            if not max_retry or (current_network_fails_count < max_retry):
                status = EXECUTION_STATE_INPROGRESS
                output_message = "Exchange server busy. Retrying..."
                if max_retry:
                    output_message = "{} ({}/{})".format(output_message, current_network_fails_count, max_retry)
                if not isinstance(additional_data, dict):
                    additional_data = {'main_result': additional_data}
                additional_data[NETWORK_FAIL_COUNT_KEY] = current_network_fails_count + 1
                result_value = json.dumps(additional_data)
            else:
                output_message = 'Reached allowed maximum ({}) network error. {}'.format(max_retry, output_message)
            break
        return output_message, result_value, status

