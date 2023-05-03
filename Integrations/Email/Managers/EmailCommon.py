# IMPORTS
import os
import re
import json
import arrow
import datetime
import copy
from SiemplifyUtils import utc_now
from urlparse import urlparse
from EmailStringUtils import safe_str_cast


# CONSTS
FWD_KEYS = ('fwd:', 'fw:')
DEAFULT_SUBJECT_TEXT = "Message Has No Subject"
DEAFULT_RESOLVED_BODY = "Message Has No Body."

DEFAULT_REGEX_MAP = {"subject": r"(?<=Subject:\* ).*|(?<=Subject: ).*",
                     "from_list": r"(?<=From:).*<(.*?)>|(?<=From: ).*",
                     "to": r"(?<=To:).*<(.*?)>|(?<=^To: ).*"}
URLS_REGEX = "(?i)(?:(?:(?:http|https)(?:://))|www(?!://))(?:[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\-\._~:/\?#\[\]@!\$&'\(\)\*\+,=])+"
DEFAULT_LIST_DELIMITER = ";"


ENCODING_UTF_8 = 'utf-8'

DEFAULT_STRING_CAST_VALUE = "Failed to string parse object"


class ProviderKeys(object):
    class EMAIL_LIBRARY(object):
        SENDER_KEY = "sender"
        SUBJECT_KEY = "subject"
        DATE_KEY = "date"
        PLAIN_BODY = "body"
        HTML_BODY = "html_body"

FILE_NAME_EVENT_FIELD_PATTERN = "file_name_{0}"
FILE_MD5_EVENT_FIELD_PATTERN = "file_md5_{0}"



class EmailCommon(object):
    def __init__(self, logger):
        self.logger = logger

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

    @staticmethod
    def handle_fwd(email, event_details):
        is_fwd = True if email.get('subject') and email['subject'].lower().startswith(FWD_KEYS) else False

        # In case of an regular email - not a forwarded email
        # This will override all same regex keys in event_details, for mapping and modeling
        if not is_fwd:
            event_details['subject'] = email.get('subject') or DEAFULT_SUBJECT_TEXT
            event_details['from'] = email.get('sender', '')
            event_details['to'] = ";".join(email.get('to')) if len(email.get('to')) else ''
        else:
            # fwd email
            # add original info
            event_details['from'] = event_details['from_list'].split(DEFAULT_LIST_DELIMITER)[-1] if event_details.get(
                'from_list') else ''
            event_details['to'] = event_details['to'].split(DEFAULT_LIST_DELIMITER)[-1] if event_details.get(
                'to') else ''
            event_details['subject'] = event_details['subject'].split(DEFAULT_LIST_DELIMITER)[0] if event_details.get(
                'subject') else DEAFULT_SUBJECT_TEXT

            # add latest info
            event_details['last_email_sender'] = email.get('sender', '')
            event_details['last_email_recipient'] = ";".join(email.get('to')) if len(email.get('to')) else ''

        return event_details

    def is_matching_exclude_patterns(self, message, subject_exclude_pattern=None, body_exclude_pattern=None):
        """
        Get first message content from list which is not matching patterns.
        :param message: {dict} Messages dict - Mail body must be utf-8 encoded.
        :param subject_exclude_pattern: {string} Subject regex exclude pattern.
        :param body_exclude_pattern: {string} Subject regex exclude pattern.
        :param extract_reply: {bool} Extract mail replay from body(Most related to standard mail integration).
        :return: {string} Relevant reply.
        """
        subject_exclude_match = None
        body_exclude_match = None

        # The sequence is important for the fallback logic.
        body_keys = ["body", "html_body"]

        if body_exclude_pattern:
            for body_key in body_keys:
                mail_body = message.get(body_key)

                if mail_body:
                    # Message received as utf-8 encoded string - treated when receiving message.
                    mail_body = mail_body.decode(ENCODING_UTF_8)

                    body_exclude_match = re.compile(body_exclude_pattern).match(mail_body)
                    # Breaks on first body that match - exit on first fall back matching.
                    if body_exclude_match:
                        break

        if subject_exclude_pattern:
            mail_subject = message[ProviderKeys.EMAIL_LIBRARY.SUBJECT_KEY]
            # Subject received as utf-8 encoded string - treated when receiving message.
            mail_subject = mail_subject.decode(ENCODING_UTF_8)
            subject_exclude_match = re.compile(subject_exclude_pattern).match(mail_subject)

        return body_exclude_match or subject_exclude_match

    def get_user_first_valid_message(self, sender, messages,
                                     subject_exclude_pattern=None, body_exclude_pattern=None):
        """
        Get all messages sent by recipient.
        :param sender: {string} sender address.
        :param messages: {list} list of message dicts.
        :param subject_exclude_pattern: {string} subject regex exclude pattern.
        :param body_exclude_pattern: {string} subject regex exclude pattern.
        :param extract_reply: {bool} Extract mail replay from body(Most related to standard mail integration).
        :return: {list} list of relevant message dicts.
        """
        if not messages:
            return None

        senders_messages = [message for message in messages if message.get(ProviderKeys.EMAIL_LIBRARY.SENDER_KEY) == sender]

        self.logger.info("Found {0} messages for sender {1}".format(len(senders_messages), sender))

        try:
            senders_messages = sorted(senders_messages, key=lambda i: i[ProviderKeys.EMAIL_LIBRARY.DATE_KEY])
        except Exception as err:
            self.logger.error("Messages does not contain date key.")
            self.logger.exception(err)

        for sequence, message in enumerate(senders_messages):
            self.logger.info(
                'Checking message match exclude pattern for sender: {0}, message sequence:{1}'.format(sender, sequence + 1))
            is_message_matching_exclude_patterns = self.is_matching_exclude_patterns(message,
                                                                                     subject_exclude_pattern,
                                                                                     body_exclude_pattern)

            if not is_message_matching_exclude_patterns:
                self.logger.info("Message in sequence {0} for sender {1} is valid.".format(sequence + 1, sender))
                return message
            self.logger.info("Message in sequence {0} for sender {1} is not valid.".format(sequence + 1, sender))

    def extract_event_details(self, content, regex_map):
        """
        Get urls, subject, from and to addresses from email body
        :param content: {str} email body
        :param regex_map: {dict} regex map
        :return: {dict} fields after parse.
        """
        result_dictionary = {}

        for key, regex_value in regex_map.items():
            try:
                regex_object = re.compile(regex_value)
                all_results = regex_object.findall(content)
                # check if in default regex - NOT Divide keys
                if key in DEFAULT_REGEX_MAP.keys():
                    if all_results:
                        # We turn to string, because c# can't accept non string values. Result_dictionary must be a string key and string value dictionary
                        result_dictionary[key] = DEFAULT_LIST_DELIMITER.join(all_results)
                else:
                    for index, result in enumerate(all_results, 1):
                        # Divide keys
                        key_name = '{0}_{1}'.format(key, index) if len(all_results) > 1 else key
                        result_dictionary[key_name] = safe_str_cast(result, default_value=DEFAULT_STRING_CAST_VALUE)
            except Exception as e:
                self.logger.error("Execution failed - {0}".format(e.message))
                self.logger.exception(e)

        return result_dictionary

    def validate_email_time(self, last_run_time, mail_dict, server_time_zone):
        """
        Compare email time to connector last run time to make sure emails are not taken more than once.
        Base on the IMAP protocol, search can be done using time filter but without time zone and hour/min
        :param last_run_time: {datetime} last execution time from file
        :param mail_dict: {Mail object}
        :param server_time_zone: {string} e.g. UTC
        :return: {Boolean}
        """
        # compare full dates
        mail_time_with_tz = arrow.get(mail_dict['date'], server_time_zone)
        self.logger.info(
            "Email time before TZ conversion: {0}. After: {1}.".format(mail_dict['date'], mail_time_with_tz))
        # Checking if email is already taken, if yes- True.
        return mail_time_with_tz <= last_run_time

    @staticmethod
    def validate_timestamp(last_run_timestamp, offset):
        """
        Validate timestamp in range
        :param last_run_timestamp: {datetime} last run timestamp
        :param offset: {datetime} last run timestamp
        :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
        """
        current_time = utc_now()
        # Check if first run
        if current_time - last_run_timestamp > datetime.timedelta(days=offset):
            return current_time - datetime.timedelta(days=offset)
        else:
            return last_run_timestamp

    def get_mapped_environment(self, original_env, map_file):
        """
        Get mapped environment alias from mapping file
        :param original_env: {str} The environment to try to resolve
        :param map_file
        :return: {str} The resolved alias (if no alias - returns the original env)
        """
        try:
            with open(map_file, 'r+') as map_file:
                mappings = json.loads(map_file.read())
        except Exception as e:
            self.logger.error(
                "Unable to read environment mappings: {}".format(str(e)))
            mappings = {}

        if not isinstance(mappings, dict):
            self.logger.LOGGER.error(
                "Mappings are not in valid format. Environment will not be mapped.")
            return original_env

        return mappings.get(original_env, original_env)

    def build_regex_map(self, regex_list):
        regex_map = copy.deepcopy(DEFAULT_REGEX_MAP)
        for regex_item in regex_list:
            try:
                if ': ' in regex_item:
                    # Split only once by ':'
                    user_regex = regex_item.split(': ', 1)
                    # check if user regex include key (regex name) and value (the regex itself)
                    if len(user_regex) >= 2:
                        regex_map.update({"regex_{}".format(unicode(user_regex[0]).encode("utf-8")): user_regex[1]})
            except Exception as e:
                self.logger.error(
                    "Unable to get parse regex list item {}. Ignoring item and continuing.".format(
                        unicode(regex_item)).encode("utf-8"))
                self.logger.exception(e)
        return regex_map
