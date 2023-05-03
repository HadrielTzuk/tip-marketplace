# This file connects common methods used in Exchange integrations connectors
import uuid
import re
import os
from TIPCommon import extract_connector_param, dict_to_flat
from base64 import b64encode
from datetime import timedelta
from SiemplifyConnectorsDataModel import CaseInfo
from SiemplifyDataModel import Attachment
from ExchangeManager import ExchangeManager, get_msg_eml_content, get_msg_attachments_content, \
    get_ics_attachments_content
from ExchangeCommon import ExchangeCommon, DEFAULT_REGEX_MAP
from SiemplifyUtils import convert_string_to_datetime, convert_string_to_unix_time, utc_now
from EmailUtils import SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY, get_html_urls
from constants import (
    DEFAULT_URLS_LIST_DELIMITER,
    ORIGINAL_EMAIL_EVENT_NAME,
    ATTACHED_EMAIL_EVENT_NAME,
    EVENTS_SYSTEM_KEYS,
    PLACEHOLDER_START,
    PLACEHOLDER_END
)
from ExchangeUtilsManager import transform_dict_keys, decode_url
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import filter_old_alerts, is_overflowed
from constants import PRIORITY_DEFAULT
from exchangelib import EWSTimeZone

# =====================================
#              CONSTANTS              #
# =====================================
DEVICE_PRODUCT = "Exchange"
VENDOR = "Microsoft"
SIEMPLIFY_EML_TIME_KEY = "eml_time"
SIEMPLIFY_ORIGINAL_EMAIL_TIME_KEY = "email_time"
CASE_NAME_PATTERN = "Exchange Monitored Mailbox <{0}>"
EMPTY_LINE = ""
UNDEFINED_MESSAGE_ID = "Cannot get message identifier"
ORIGINAL_MESSAGE_TYPE = ".eml"
EML_ATTACHMENT_DESCRIPTION = "This is the original message as EML"


def extract_connector_parameter(siemplify, param_name, default_value=None, input_type=str, is_mandatory=False, print_value=False):
    """
    Wraps TIPCommon.extract_connector_param() to extract str by default as a connector param
    :param siemplify: {SiemplifyConnectorExecution} Instance of the SiemplifyConnectorExecution representing connector scope
    :param param_name: {str} Name of the connector configuration parameter
    :param default_value: {object} Default value depending on the input_type
    :param input_type: {type} Type of the expected parameter
    :param is_mandatory: {bool} True - method would raise an exception, if parameter is missing, False - no exception.
    :param print_value: {bool} Print extracted parameter value to the log
    :return: {object} Connector parameter value
    """
    return extract_connector_param(siemplify=siemplify,
                                   param_name=param_name,
                                   default_value=default_value,
                                   input_type=input_type,
                                   is_mandatory=is_mandatory,
                                   print_value=print_value)


def init_manager(connector_scope):
    """
    Extracts all required parameters and initiates an ExchangeManager
    :param connector_scope: {SiemplifyConnectorExecution} Instance of the SiemplifyConnectorExecution representing connector scope
    :return: {ExchangeManager} ExchangeManager instance
    """
    server_ip = extract_connector_parameter(siemplify=connector_scope, param_name="Server IP", is_mandatory=True)
    domain = extract_connector_parameter(siemplify=connector_scope, param_name="Domain", is_mandatory=True)
    username = extract_connector_parameter(siemplify=connector_scope, param_name="Username", is_mandatory=True)
    password = extract_connector_parameter(siemplify=connector_scope, param_name="Password", is_mandatory=True)
    mail_address = extract_connector_parameter(siemplify=connector_scope, param_name="Mail Address", is_mandatory=True)
    use_domain_in_auth = extract_connector_parameter(
        siemplify=connector_scope,
        param_name="Use Domain For Authentication",
        input_type=bool,
        default_value=True
    )
    verify_ssl = extract_connector_parameter(siemplify=connector_scope, param_name="Verify SSL", input_type=bool,
                                             default_value=False)

    return ExchangeManager(
        exchange_server_ip=server_ip,
        domain=domain,
        username=username,
        password=password,
        user_mail_address=mail_address,
        use_domain_in_auth=use_domain_in_auth,
        siemplify_logger=connector_scope.LOGGER,
        verify_ssl=verify_ssl
    )


def set_proxy(connector_scope):
    """
    Extract proxy settings from connector configurations. If they are set, tries to connect to a proxy
    :param connector_scope: {SiemplifyConnectorExecution} Instance of the SiemplifyConnectorExecution representing connector scope
    """
    proxy_server = extract_connector_parameter(siemplify=connector_scope, param_name="Proxy Server Address")
    proxy_username = extract_connector_parameter(siemplify=connector_scope, param_name="Proxy Username")
    proxy_password = extract_connector_parameter(siemplify=connector_scope, param_name="Proxy Password")
    if proxy_server:
        try:
            connector_scope.LOGGER.info("Configuring proxy settings")
            ExchangeCommon.set_proxy(proxy_server, proxy_username, proxy_password)
        except Exception as e:
            connector_scope.LOGGER.error("Unable to configure proxy. Trying to continue without proxy.")
            connector_scope.LOGGER.exception(e)


def filter_emails_with_regexes(emails, subject_exclude_regex=None, body_exclude_regex=None):
    """
    Walks through all provided emails, matches their subject and all possible body fields against regexes and takes just non matching ones.
    :param emails: {list} List of email dictionaries
    :param subject_exclude_regex: {str} String representing regex to exclude email by matching subject
    :param body_exclude_regex: {str} String representing regex to exclude email by matching body
    :return: {list} List of filtered email dictionaries
    """
    filtered_emails = []

    for email in emails:
        if not is_matching_exclude_patterns(email, subject_exclude_regex, body_exclude_regex):
            filtered_emails.append(email)

    return filtered_emails


def is_matching_exclude_patterns(message, subject_exclude_pattern=None, body_exclude_pattern=None):
    """
    Get first message content from list which is not matching patterns.
    :param message: {exchangelib.Message} Message object, which we have received from exchangelib
    :param subject_exclude_pattern: {str} Regex pattern, which would exclude emails with matching subject.
    :param body_exclude_pattern: {str} Regex pattern, which would exclude emails with matching body.
    :return: {bool} Relevant reply: True if matches one of the exclude patterns; False - otherwise.
    """
    body_parts = [message.text_body, message.unique_body]

    if body_exclude_pattern:
        for part in body_parts:
            if part and re.findall(body_exclude_pattern, part):
                return True

    if subject_exclude_pattern:
        if message.subject and re.findall(subject_exclude_pattern, message.subject):
            return True

    return False


class ExchangeConnector(object):
    def __init__(self, connector_scope, exchange_manager, exchange_common, email_utils, offset_time_in_days,
                 environment_field_name, environment_regex, test_run, headers_to_add_to_events,
                 extract_html_content_urls=False, time_interval=0, connector_starting_time=None,
                 case_name_template=None, alert_name_template=None, padding_period=None):
        self.exchange_manager = exchange_manager
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER
        self.exchange_common = exchange_common
        self.email_utils = email_utils
        self.regex_map = exchange_common.build_regex_map(
            connector_scope.whitelist,
            {"urls": DEFAULT_REGEX_MAP.get("urls")}
        )
        self.environment_field_name = environment_field_name
        self.environment_regex = environment_regex
        self.test_run = test_run
        self.headers_to_add_to_events = headers_to_add_to_events
        self.extract_html_content_urls = extract_html_content_urls
        self.time_interval = time_interval
        self.connector_starting_time = connector_starting_time
        self.last_run = self.get_last_run(offset_time_in_days, padding_period)
        self.connector_scope.LOGGER.info("Last run time: {}".format(self.last_run))
        self.case_name_template = case_name_template
        self.alert_name_template = alert_name_template
        self.email_folder_pairs = {}
        self.common_environment = GetEnvironmentCommonFactory.create_environment_manager(
            self.connector_scope, self.environment_field_name, self.environment_regex
        )

    def get_last_run(self, offset_time_in_days, padding_period=None):
        """
        Get connector's last  run time.
        :param offset_time_in_days: {int} Amount of days back.
        :param padding_period: {int} Padding period in minutes to calculate last run time
        :return: {str} Last run time.
        """
        last_run_time = self.exchange_common.validate_max_days_backwards(
            self.connector_scope.fetch_timestamp(datetime_format=True),
            offset_time_in_days
        )

        if padding_period is not None and last_run_time > utc_now() - timedelta(minutes=padding_period):
            last_run_time = utc_now() - timedelta(minutes=padding_period)
            # Change tzinfo to be EWSTimeZone timezone object
            last_run_time = last_run_time.replace(tzinfo=EWSTimeZone.timezone('UTC'))
            self.connector_scope.LOGGER.info(f"Last success time is greater than email padding period. Unix: "
                                             f"{last_run_time.timestamp()} will be used as last success time")

        return last_run_time

    def create_event(self, original_email, parsed_email, is_original_event=False, prefix=None, event_index=None):
        """
        Create an event from an eml content.
        :param original_email: {exchangelib.Message} The original message that contained the parsed EML
        :param parsed_email: {dict} Parsed EML content.
        :param is_original_event: {bool} True if parsed_email is the original email
        :param prefix: {str} Prefix for event keys
        :param event_index: {int} Index of the event
        :return: {dict} event dict.
        """
        # Create event
        try:
            self.connector_scope.LOGGER.info("Creating event from EML/MSG/ICS")
            try:
                str_time = (original_email.datetime_created or utc_now()).isoformat()
                parsed_email[SIEMPLIFY_ORIGINAL_EMAIL_TIME_KEY] = convert_string_to_unix_time(str_time)
            except Exception as err:
                parsed_email[SIEMPLIFY_ORIGINAL_EMAIL_TIME_KEY] = 1
                error_message = "Failed to fetch original email time for mail with ID: {0}".format(
                    original_email.message_id)
                self.logger.error(error_message)
                self.logger.exception(err)

            try:
                eml_time = parsed_email.get(SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY, 1)
            except Exception as err:
                eml_time = 1
                error_message = "Failed to fetch eml time for mail with ID: {0}".format(original_email.message_id)
                self.logger.error(error_message)
                self.logger.exception(err)

            parsed_email[SIEMPLIFY_EML_TIME_KEY] = eml_time
            parsed_email['device_product'] = DEVICE_PRODUCT
            parsed_email['device_vendor'] = VENDOR
            parsed_email['event_name'] = ORIGINAL_EMAIL_EVENT_NAME
            parsed_email['monitored_mailbox_name'] = self.exchange_manager.account
            parsed_email['email_folder'] = self.email_folder_pairs.get(original_email.message_id)

            if not is_original_event:
                parsed_email['original_message_id'] = original_email.message_id
                parsed_email['event_name'] = ATTACHED_EMAIL_EVENT_NAME

            flat_eml = dict_to_flat(parsed_email)

            return transform_dict_keys(flat_eml, prefix, event_index, EVENTS_SYSTEM_KEYS) if prefix else flat_eml
        except Exception as err:
            self.connector_scope.LOGGER.error("Failed creating an event")
            self.connector_scope.LOGGER.exception(err)

        return {}

    def extract_regex_from_content(self, parsed_email):
        """
        Extract regex from email's body.
        :param parsed_email: {dict} Parsed EML content.
        :return: {dict} Updated parsed email which contains extracted regex.
        """
        try:
            self.connector_scope.LOGGER.info("Extracting regex from EML/MSG/ICS content.")
            extracted_dict = self.exchange_common.extract_regex_from_content(parsed_email.get("body", ""), self.regex_map)
            urls = [decode_url(url) for url in [extracted_dict.get("urls", ""), parsed_email.get("urls", "")] if url]

            if urls:
                extracted_dict['urls'] = DEFAULT_URLS_LIST_DELIMITER.join(urls)

            parsed_email.update(extracted_dict)

        except Exception as e:
            # If the extract regex fails
            self.connector_scope.LOGGER.error("Failed to extract regex from the EML/MSG/ICS.")
            self.connector_scope.LOGGER.exception(e)

        return parsed_email

    def get_events_for_attachments(self, original_msg, prefix=None):
        """
        Create and return evens from original message attachments only EML/MSG/ICS.
        :param original_msg: {dict} Parsed EML content.
        :param prefix: {str} Prefix for events keys
        :return: list , list events: Events list created from attachments, file_names: list of file names only EML/MSG/ICS
        """
        events = []
        attachments, original_ics_file_names = self.get_attachments_from_message(original_msg)
        file_names = original_ics_file_names
        for index, value in enumerate(attachments):
            parsed_email_filename, parsed_email = value
            self.connector_scope.LOGGER.info("Processing parsed email: {}".format(parsed_email_filename))
            parsed_email = self.extract_regex_from_content(parsed_email)

            if self.extract_html_content_urls:
                urls, original_src_urls = get_html_urls(parsed_email.get("html_body", ""))
                parsed_email.update({"urls_from_html_part": original_src_urls})
                parsed_email.update({"visible_urls_from_html_part": urls})

            events.append(self.create_event(original_msg, parsed_email, prefix=prefix, event_index=index+1))
            file_names.append(parsed_email_filename)

        return events, file_names

    def get_new_emails(self, unread_only, folder_names, existing_ids):
        """
        Get new emails.
        :param unread_only: {bool} If True will load only unread emails.
        :param folder_names: {list} List of folder names to fetch the emails
        :param existing_ids: {list} The list of existing ids
        :return: {list} List of fetched emails
        """
        self.connector_scope.LOGGER.info("Collecting emails.")
        emails = []

        for folder_name in folder_names:
            folder_emails = self.exchange_manager.receive_mail(
                time_filter=self.last_run,
                end_time_filter=get_end_time_filter(self.last_run, self.time_interval, self.connector_starting_time),
                only_unread=unread_only,
                folder_name=folder_name
            )

            emails.extend(folder_emails)
            self.email_folder_pairs.update({folder_email.message_id: folder_name for folder_email in folder_emails})

        filtered_emails = filter_old_alerts(self.connector_scope, emails, existing_ids, "message_id")
        self.connector_scope.LOGGER.info("Found {} emails.".format(len(filtered_emails)))
        return sorted(filtered_emails, key=lambda filtered_email: filtered_email.datetime_received, reverse=True)

    def get_eml_attachments(self, original_msg):
        """
        Get eml attachments.
        :param original_msg: {dict} If True will load only unread emails.
        :return: {list} EML attachments list exported from original message
        """
        attachments = []
        eml_attachments = get_msg_eml_content(original_msg)

        for eml_filename, eml_content in eml_attachments.items():
            try:
                self.connector_scope.LOGGER.info("Parsing EML: {}".format(eml_filename))

                parsed_eml = self.email_utils.convert_siemplify_eml_to_connector_eml(
                    eml_content, is_v2_connector=True, headers_to_add=self.headers_to_add_to_events)

                attachments.append((eml_filename, parsed_eml))

            except Exception as err:
                self.connector_scope.LOGGER.error("Failed Parsing EML content")
                self.connector_scope.LOGGER.exception(err)
        return attachments

    def get_msg_attachments(self, original_msg):
        """
        Get msg attachments.
        :param original_msg: {dict} If True will load only unread emails.
        :return: {list} MSG attachments list exported from original message
        """
        attachments = []
        msg_attachments = get_msg_attachments_content(original_msg)
        for msg_filename, msg_content in msg_attachments.items():
            try:
                self.connector_scope.LOGGER.info("Parsing MSG: {}".format(msg_filename))

                parsed_msg = self.email_utils.convert_siemplify_msg_to_connector_msg(
                    msg_content,
                    is_v2_connector=True)

                attachments.append((msg_filename, parsed_msg))

            except Exception as err:
                self.connector_scope.LOGGER.error("Failed Parsing MSG content")
                self.connector_scope.LOGGER.exception(err)

        return attachments

    def get_ics_attachments(self, original_msg):
        """
        Get ics attachments.
        :param original_msg: {dict} If True will load only unread emails.
        :return: {list} ICS attachments list exported from original message
        """
        attachments = []
        original_file_names = []
        ics_attachments = get_ics_attachments_content(original_msg)

        for ics_file_name, ics_content in ics_attachments.items():
            try:
                self.connector_scope.LOGGER.info("Parsing ICS: {}".format(ics_file_name))
                original_file_names.append(ics_file_name)
                parsed_ics_list = self.email_utils.convert_siemplify_ics_to_connector_msg(ics_content)
                if len(parsed_ics_list) > 1:
                    file_name, file_extension = os.path.splitext(ics_file_name)
                    for index, ics in enumerate(parsed_ics_list, 1):
                        new_file_name = "{}_{}{}".format(file_name, index, file_extension)
                        attachments.append((new_file_name, ics))
                elif len(parsed_ics_list) == 1:
                    attachments.append((ics_file_name, parsed_ics_list[0]))

            except Exception as err:
                self.connector_scope.LOGGER.error("Failed Parsing ICS content")
                self.connector_scope.LOGGER.exception(err)

        return attachments, original_file_names

    def get_attachments_from_message(self, original_msg):
        """
        Get attachments from message.
        :param original_msg: {dict} If True will load only unread emails.
        :return: {list} ICS attachments list exported from original message
        """
        eml_attachments = self.get_eml_attachments(original_msg)
        msg_attachments = self.get_msg_attachments(original_msg)
        # since we are changing the name of ics file in some cases, we need to get the original one
        ics_attachments, original_ics_file_names = self.get_ics_attachments(original_msg)

        self.logger.info(
            'Found {0} EMLs, {1} MSGs and {2} ICSs for mail with ID: {3}'.format(
                len(eml_attachments),
                len(msg_attachments),
                len(ics_attachments),
                original_msg.message_id))

        return eml_attachments + msg_attachments + ics_attachments, original_ics_file_names

    def save_timestamp(self, emails, time_interval=0):
        """
        Save timestamp.
        :param emails: {list} List of emails containing timestamp.
        :param time_interval: {int} Time interval in minutes.
        """
        # Last execution time is set to the newest message time
        last_exe_time = emails[0].datetime_received if emails \
            else min(self.connector_starting_time, self.last_run + timedelta(minutes=time_interval))
        # Convert to EWStime to str in order to convert to datetime
        new_last_exe_datetime = convert_string_to_datetime(last_exe_time.isoformat())
        self.connector_scope.save_timestamp(datetime_format=True,
                                            new_timestamp=new_last_exe_datetime)

    def create_case_from_message(self, msg, attach_original_eml, original_mail_prefix=None, attached_mail_prefix=None):
        """
        Create case from message.
        :param msg: {Message} Original message received from exchange lib
        :param attach_original_eml: {bool} Attach original eml if True
        :param original_mail_prefix: {str} Prefix for original mail event keys
        :param attached_mail_prefix: {str} Prefix for attached mail event keys
        """
        events_for_attachment, processed_file_names = self.get_events_for_attachments(msg, prefix=attached_mail_prefix)
        parsed_original_msg = self.email_utils.convert_siemplify_eml_to_connector_eml(
            msg.mime_content, is_v2_connector=True, exclude_attachments=processed_file_names,
            headers_to_add=self.headers_to_add_to_events)

        return self.generate_case_info(
            original_msg=msg,
            parsed_msg=parsed_original_msg,
            events=events_for_attachment,
            attach_original_eml=attach_original_eml,
            prefix=original_mail_prefix,
            processed_file_names=processed_file_names,
            is_original_email=True
        )

    def create_cases_from_message(self, msg, attach_original_eml, original_mail_prefix=None, attached_mail_prefix=None):
        """
        Create cases from message and email attachments.
        :param msg: {Message} Original message received from exchange lib
        :param attach_original_eml: {bool} Attach original eml if True
        :param original_mail_prefix: {str} Prefix for original mail event keys
        :param attached_mail_prefix: {str} Prefix for attached mail event keys
        """
        attachments, original_ics_file_names = self.get_attachments_from_message(msg)
        processed_file_names = [name for name, attachment in attachments]

        parsed_original_msg = self.email_utils.convert_siemplify_eml_to_connector_eml(
            msg.mime_content, is_v2_connector=True, exclude_attachments=processed_file_names,
            headers_to_add=self.headers_to_add_to_events)

        original_email_case_info = self.generate_case_info(
            original_msg=msg,
            parsed_msg=parsed_original_msg,
            events=[],
            attach_original_eml=attach_original_eml,
            prefix=original_mail_prefix,
            processed_file_names=processed_file_names,
            is_original_email=True
        )

        cases_info = [original_email_case_info]

        if attachments:
            for name, attachment in attachments:
                cases_info.append(
                    self.generate_case_info(
                        original_msg=msg,
                        parsed_msg=attachment,
                        events=[original_email_case_info.events[0]],
                        attach_original_eml=False,
                        prefix=attached_mail_prefix
                    )
                )
    
        return cases_info

    def generate_case_info(self, original_msg, parsed_msg, events, attach_original_eml, prefix=None,
                           processed_file_names=[], is_original_email=False):
        parsed_msg = self.extract_regex_from_content(parsed_msg)

        if self.extract_html_content_urls:
            urls, original_src_urls = get_html_urls(parsed_msg.get("html_body", ""))
            parsed_msg.update({"urls_from_html_part": original_src_urls})
            parsed_msg.update({"visible_urls_from_html_part": urls})

        event_details = self.create_event(original_msg, parsed_msg, is_original_event=is_original_email, prefix=prefix)
        self.logger.info("Event dict created.")

        # Construct case name if case name template provided
        case_name = (
            transform_template_string(self.case_name_template, event_details)
            if self.case_name_template
            else ""
        )
        # Construct alert name if alert name template provided
        alert_name = (
            transform_template_string(self.alert_name_template, event_details)
            if self.alert_name_template
            else ""
        )

        if case_name:
            event_details["custom_case_name"] = case_name

        if prefix:
            SIEMPLIFY_EML_TIME_KEY_PREFIXED = f"{prefix}_{SIEMPLIFY_EML_TIME_KEY}"
        else:
            SIEMPLIFY_EML_TIME_KEY_PREFIXED = SIEMPLIFY_EML_TIME_KEY

        # Create case info object
        case_info = CaseInfo()
        case_info.name = (
                alert_name
                or CASE_NAME_PATTERN.format(
                    self.exchange_manager.account.primary_smtp_address
                    or EMPTY_LINE
                )
        )
        case_info.rule_generator = case_info.name
        case_info.start_time = event_details.get(SIEMPLIFY_EML_TIME_KEY_PREFIXED, 1)
        case_info.end_time = case_info.start_time
        case_info.identifier = original_msg.message_id or UNDEFINED_MESSAGE_ID
        case_info.ticket_id = case_info.identifier
        case_info.display_id = case_info.identifier if is_original_email else str(uuid.uuid4())
        case_info.priority = PRIORITY_DEFAULT
        case_info.device_vendor = VENDOR
        case_info.device_product = DEVICE_PRODUCT
        case_info.attachments = []

        if is_original_email:
            # append attachments to case wall
            for attachment in original_msg.attachments:
                try:
                    if processed_file_names and attachment.name in processed_file_names:
                        continue
                except:
                    pass
                attachment_for_case = self.attach_file_to_case(attachment.name, attachment.content)
                if attachment_for_case:
                    case_info.attachments.append(attachment_for_case)

        case_info.environment = self.common_environment.get_environment(event_details)
        case_info.events = [event_details] + events

        if attach_original_eml:
            try:
                attachment_object = self.create_attachment_object(
                    original_msg.mime_content,
                    parsed_msg.get('subject', ""))
                # Add to case_info
                case_info.attachments.append(attachment_object)
                self.connector_scope.LOGGER.info("Successfully attached original message as EML.")
            except Exception as e:
                self.connector_scope.LOGGER.error("Failed to attach original EML. Error: {0}.".format(e))

        return case_info

    @staticmethod
    def create_attachment_object(original_msg_content, attachment_name):
        """
        Create attachment object with the original email
        :param original_msg_content: {string} original message content
        :param attachment_name: {string} email subject as the attachment name
        :return: {Attachment} of attachment object
        """
        base64_blob = b64encode(original_msg_content).decode()
        attachment_object = Attachment(
            case_identifier=None,
            alert_identifier=None,
            base64_blob=base64_blob,
            attachment_type=ORIGINAL_MESSAGE_TYPE,
            name=attachment_name,
            description=EML_ATTACHMENT_DESCRIPTION,
            is_favorite=False,
            orig_size=len(original_msg_content),
            size=len(base64_blob))
        return attachment_object

    def attach_file_to_case(self, file_name, file_content):
        self.logger.info("Checking EML and MSG attachments to attach to the case")

        try:
            if isinstance(file_content, str):
                file_content = file_content.encode()
            self.logger.info("Attached {} file to the case".format(file_name))
            return create_siemplify_case_wall_attachment_object(file_name, file_content)
        except Exception as e:
            self.logger.error("Failed to attach {} to the case wall".format(file_name))
            self.logger.exception(e)

    def is_original_case_info_overflow(self, case_info):
        is_overflow = is_overflowed(self.connector_scope, case_info, self.test_run)

        if is_overflow:
            # Skipping this alert (and dot ingest it to siemplify)
            self.connector_scope.LOGGER.info(
                "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.".format(
                    alert_name=case_info.rule_generator,
                    alert_identifier=case_info.ticket_id,
                    environment=case_info.environment,
                    product=case_info.device_product))

        return is_overflow

    def mark_emails_as_read(self, fetched_emails):
        for email in fetched_emails:
            try:
                email.is_read = True
                email.save()
            except Exception as e:
                self.logger.error("Cannot mark the message-{} as read, {}".format(email.message_id, e))
            self.logger.info("Message '{}' marked as read".format(email.message_id))


def create_siemplify_case_wall_attachment_object(full_file_name, file_contents):
    # type: (bytes, str) -> Attachment
    """
    Create attachment object with the original email
    :param full_file_name: {string} File name of the attachment
    :param file_contents: {string} Attachment content as a string
    :return: {Attachment} of attachment object
    """
    base64_blob = b64encode(file_contents).decode()

    file_name, file_extension = os.path.splitext(full_file_name)
    attachment_object = Attachment(
        case_identifier=None,
        alert_identifier=None,
        base64_blob=base64_blob,
        attachment_type=file_extension,
        name=file_name,
        description="Original email attachment",
        is_favorite=False,
        orig_size=len(file_contents),
        size=len(base64_blob))
    return attachment_object


def get_end_time_filter(last_run, time_interval, connector_starting_time=None):
    """
    Get end time filter from last run time and time interval
    :param last_run: {datetime} Last run datetime
    :param time_interval: {int} Time interval in minutes
    :param connector_starting_time: {datetime} Connector starting time
    :return: {datetime} End time filter
    """
    if not time_interval:
        return

    return min(connector_starting_time, last_run + timedelta(minutes=time_interval))


def transform_template_string(template, event):
    """
    Transform string containing template using event data
    :param template: {str} String containing template
    :param event: {dict} Case event
    :return: {str} Transformed string
    """
    index = 0

    while PLACEHOLDER_START in template[index:] and PLACEHOLDER_END in template[index:]:
        partial_template = template[index:]
        start, end = partial_template.find(PLACEHOLDER_START) + len(PLACEHOLDER_START),\
                     partial_template.find(PLACEHOLDER_END)
        substring = partial_template[start:end]
        value = event.get(substring) if event.get(substring) else ""
        template = template.replace(f"{PLACEHOLDER_START}{substring}{PLACEHOLDER_END}", value, 1)
        index = index + start + len(value)

    return template
