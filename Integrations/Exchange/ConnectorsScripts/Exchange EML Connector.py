import os
import sys
# -*- coding: utf-8 -*-
from base64 import b64encode
from SiemplifyUtils import output_handler
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import CaseInfo
from SiemplifyDataModel import Attachment
from ExchangeManager import get_msg_eml_content, get_msg_attachments_content, get_ics_attachments_content
from ExchangeCommon import ExchangeCommon
from ExchangeConnectors import extract_connector_parameter, init_manager, set_proxy, filter_emails_with_regexes
from SiemplifyUtils import convert_string_to_datetime, convert_string_to_unix_time, utc_now
from EmailUtils import EmailUtils, SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY, get_unicode_str, get_html_urls
from TIPCommon import dict_to_flat, is_overflowed, read_ids, write_ids, filter_old_alerts
from EnvironmentCommon import GetEnvironmentCommonFactory
from constants import STORED_IDS_LIMIT, PRIORITY_DEFAULT


# =====================================
#              CONSTANTS              #
# =====================================
CONNECTOR_NAME = "Exchange EML Connector"
DEVICE_PRODUCT = "Exchange"
VENDOR = "Microsoft"
EVENT_MAPPING_FIELD = "Email file"
DEFAULT_SUBJECT_TEXT = "Message Has No Subject"
EML_SUBJECT_KEY = 'subject'

SIEMPLIFY_EML_TIME_KEY = "eml_time"
SIEMPLIFY_ORIGINAL_EMAIL_TIME_KEY = "email_time"


class ExchangeConnector(object):
    def __init__(self, connector_scope, exchange_manager, exchange_common, email_utils):
        self.exchange_manager = exchange_manager
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER
        self.exchange_common = exchange_common
        self.email_utils = email_utils

    def create_event(self, original_email, parsed_email):
        """
        Create an event from an eml content.
        :param parsed_email: {dict} Parsed EML content.
        :param original_email: {exchangelib.Message} The original message that contained the parsed EML
        :return: {dict} event dict.
        """
        # Create event
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
        parsed_email['original_message_id'] = original_email.message_id
        parsed_email['siemplify_event_mapping_field'] = EVENT_MAPPING_FIELD
        parsed_email['subject'] = original_email.subject or ' '
        flat_eml = dict_to_flat(parsed_email)
        return flat_eml

    def create_case_info(self, email_id, event, common_environment):
        """
        Get alerts from Email
        :param email_id: {dict} An email data
        :param event: {dict} Raw EML content.
        :param common_environment: (obj) A GetEnvironmentCommonFactory initialized object
        :return: {CaseInfo} case
        """
        case_info = CaseInfo()
        self.logger.info("Creating Case for Email {}".format(email_id))
        # Create the CaseInfo
        try:
            case_info.name = event.get(EML_SUBJECT_KEY, DEFAULT_SUBJECT_TEXT)
            case_info.rule_generator = case_info.name
            case_info.identifier = email_id
            case_info.ticket_id = case_info.identifier
            case_info.priority = PRIORITY_DEFAULT
            case_info.device_vendor = VENDOR
            case_info.device_product = DEVICE_PRODUCT
            case_info.display_id = case_info.identifier
            case_info.environment = common_environment.get_environment(event)
            case_info.events = [event]

            # Case times are the email time
            case_info.start_time = case_info.end_time = event.get(SIEMPLIFY_EML_TIME_KEY, 1)

        except KeyError as e:
            raise KeyError("Mandatory key is missing: {}. Skipping email.".format(
                get_unicode_str(e.message)))

        return case_info


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


def attach_file_to_case(case, attachments_dict, logger):
    """
    Attaches files from {file_name, file_contents} type dict to the case wall.
    :param case: {SiemplifyConnectorDataModel.CaseInfo} An instance of the CaseInfo class representing the case
    :param attachments_dict: {dict} Should be a mapping of attachment file_name to the actual MIME-valid file contents
    :param logger: {SiemplifyLogger} An instance of the SiemplifyLogger to be used
    """
    logger.info("Checking EML and MSG attachments to attach to the case")

    for file_name, file_contents in attachments_dict.items():
        try:
            if isinstance(file_contents, str):
                file_contents = file_contents.encode()
            attachment = create_siemplify_case_wall_attachment_object(file_name, file_contents)
            case.attachments.append(attachment)
            logger.info("Attached {} file to the case".format(file_name))
        except Exception as e:
            logger.error("Failed to attach {} to the case wall".format(file_name))
            logger.exception(e)


@output_handler
def main(test_run=False):
    cases = []

    connector_scope = SiemplifyConnectorExecution()
    connector_scope.script_name = CONNECTOR_NAME

    if test_run:
        connector_scope.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    connector_scope.LOGGER.info("==================== Main - Param Init ====================")

    folder_name = extract_connector_parameter(siemplify=connector_scope, param_name="Folder Name", is_mandatory=True)
    environment_field_name = extract_connector_parameter(siemplify=connector_scope, param_name="Environment Field Name")
    environment_regex = extract_connector_parameter(siemplify=connector_scope, param_name="Environment Regex Pattern")
    unread_only = extract_connector_parameter(siemplify=connector_scope, param_name="Unread Emails Only",
                                              is_mandatory=True, input_type=bool)
    encode_utf8 = extract_connector_parameter(siemplify=connector_scope, param_name="Encode Data as UTF-8",
                                              is_mandatory=True, input_type=bool)
    mark_as_read = extract_connector_parameter(siemplify=connector_scope, param_name="Mark Emails as Read",
                                               input_type=bool, default_value=False)
    max_days_backwards = extract_connector_parameter(siemplify=connector_scope, param_name="Max Days Backwards",
                                                     input_type=int, default_value=1)
    attach_eml_files = extract_connector_parameter(siemplify=connector_scope,
                                                   param_name="Attach EML or MSG File to the Case Wall",
                                                   input_type=bool, default_value=False)
    subject_exclude_regex = extract_connector_parameter(siemplify=connector_scope, param_name="Exclusion Subject Regex")
    body_exclude_regex = extract_connector_parameter(siemplify=connector_scope, param_name="Exclusion Body Regex")
    extract_html_content_urls = extract_connector_parameter(siemplify=connector_scope,
                                                            param_name="Extract urls from HTML email part?",
                                                            input_type=bool)

    set_proxy(connector_scope)

    connector_scope.LOGGER.info("Connecting to Exchange.")
    email_client = init_manager(connector_scope)
    email_common = ExchangeCommon(connector_scope.LOGGER, email_client)
    email_utils = EmailUtils()
    exchange_connector = ExchangeConnector(connector_scope, email_client, email_common, email_utils)
    common_environment = GetEnvironmentCommonFactory.create_environment_manager(
        siemplify=connector_scope,
        environment_field_name=environment_field_name,
        environment_regex_pattern=environment_regex
    )

    connector_scope.LOGGER.info("------------------- Main - Started -------------------")
    try:
        last_run = email_common.validate_max_days_backwards(
            connector_scope.fetch_timestamp(datetime_format=True),
            max_days_backwards)

        connector_scope.LOGGER.info("Last run time: {}".format(last_run))

        # Read already existing alerts ids
        existing_ids = read_ids(connector_scope)
        connector_scope.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing ids")

        connector_scope.LOGGER.info("Collecting emails.")
        emails = email_client.receive_mail(
            time_filter=last_run,
            only_unread=unread_only,
            folder_name=folder_name,
            mark_as_read=mark_as_read and not test_run)

        if mark_as_read and test_run:
            connector_scope.LOGGER.info("This is a TEST run. Email won't be marked as read")

        emails = filter_old_alerts(connector_scope, emails, existing_ids, "message_id")

        connector_scope.LOGGER.info("Found {} emails.".format(len(emails)))

        emails = filter_emails_with_regexes(emails, subject_exclude_regex, body_exclude_regex)
        connector_scope.LOGGER.info("Number of emails after filtering by regexes {}".format(len(emails)))

        # Last execution time is set to the newest message time
        new_last_exe_time = emails[0].datetime_received if emails else last_run

        if test_run:
            emails = emails[:1]
            connector_scope.LOGGER.info("Trimmed number of emails for processing to 1, since it's a test run")

        regex_map = email_common.build_regex_map(connector_scope.whitelist)

        connector_scope.LOGGER.info("Fetching emails according to timestamp.")

        for original_msg in emails:
            try:
                connector_scope.LOGGER.info(
                    'Running on email with ID: {0}'.format(original_msg.message_id))

                eml_attachments = get_msg_eml_content(original_msg)
                msg_attachments = get_msg_attachments_content(original_msg)
                ics_attachments = get_ics_attachments_content(original_msg)

                connector_scope.LOGGER.info(
                    'Found {0} EMLs, {1} MSGs and {2} ICSs for mail with ID: {3}'.format(
                        len(eml_attachments),
                        len(msg_attachments),
                        len(ics_attachments),
                        original_msg.message_id))

                parsed_email_attachments = []

                for eml_filename, eml_content in eml_attachments.items():
                    try:
                        connector_scope.LOGGER.info("Parsing EML: {}".format(eml_filename))

                        parsed_eml = email_utils.convert_siemplify_eml_to_connector_eml(
                            eml_content,
                            convert_body_to_utf8=encode_utf8,
                            convert_subject_to_utf8=encode_utf8,
                            encode_attachments_as_base64=True)

                        parsed_email_attachments.append((eml_filename, parsed_eml))

                    except Exception as err:
                        connector_scope.LOGGER.error("Failed Parsing EML content")
                        connector_scope.LOGGER.exception(err)

                for msg_filename, msg_content in msg_attachments.items():
                    try:
                        connector_scope.LOGGER.info("Parsing MSG: {}".format(msg_filename))

                        parsed_msg = email_utils.convert_siemplify_msg_to_connector_msg(
                            msg_content,
                            convert_body_to_utf8=encode_utf8,
                            convert_subject_to_utf8=encode_utf8,
                            encode_attachments_as_base64=True)

                        parsed_email_attachments.append((msg_filename, parsed_msg))

                    except Exception as err:
                        connector_scope.LOGGER.error("Failed Parsing MSG content")
                        connector_scope.LOGGER.exception(err)

                for ics_file_name, ics_content in ics_attachments.items():
                    try:
                        connector_scope.LOGGER.info("Parsing ICS: {}".format(ics_file_name))

                        parsed_ics_list = email_utils.convert_siemplify_ics_to_connector_msg(ics_content)
                        if len(parsed_ics_list) > 1:
                            file_name, file_extension = os.path.splitext(ics_file_name)
                            for index, ics in enumerate(parsed_ics_list, 1):
                                new_file_name = "{}_{}{}".format(file_name, index, file_extension)
                                parsed_email_attachments.append((new_file_name, ics))
                        elif len(parsed_ics_list) == 1:
                            parsed_email_attachments.append((ics_file_name, parsed_ics_list[0]))

                    except Exception as err:
                        connector_scope.LOGGER.error("Failed Parsing ICS content")
                        connector_scope.LOGGER.exception(err)

                for parsed_email_filename, parsed_email in parsed_email_attachments:
                    connector_scope.LOGGER.info("Processing parsed email: {}".format(parsed_email_filename))

                    try:
                        try:
                            connector_scope.LOGGER.info("Extracting regex from EML/MSG content.")
                            parsed_email.update(
                                email_common.extract_regex_from_content(
                                    parsed_email.get("body", ""), regex_map))

                        except Exception as e:
                            # If the extract regex fails
                            connector_scope.LOGGER.error("Failed to extract regex from the EML/MSG.")
                            connector_scope.LOGGER.exception(e)

                        if extract_html_content_urls:
                            try:
                                urls, original_src_urls = get_html_urls(parsed_email.get("HTML Body", ""))
                                parsed_email.update({
                                    "urls_from_html_part": original_src_urls,
                                    "visible_urls_from_html_part": urls
                                })

                            except Exception as e:
                                # If the extraction of html urls fails
                                connector_scope.LOGGER.error("Failed to extract HTML URLs")
                                connector_scope.LOGGER.exception(e)

                        connector_scope.LOGGER.info("Creating event from EML/MSG")
                        event = exchange_connector.create_event(original_msg, parsed_email)

                    except Exception as err:
                        connector_scope.LOGGER.error("Failed creating an event")
                        connector_scope.LOGGER.exception(err)
                        event = {}

                    try:
                        # Add to case_info
                        case_info = exchange_connector.create_case_info(
                            original_msg.message_id,
                            event,
                            common_environment)

                        # Update existing alerts
                        existing_ids.append(original_msg.message_id)

                        # Check if alert overflow
                        if is_overflowed(connector_scope, case_info, test_run):
                            # Skipping this alert (and dot ingest it to siemplify)
                            connector_scope.LOGGER.info(
                                "{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.".format(
                                    alert_identifier=case_info.ticket_id,
                                    environment=case_info.environment,
                                    product=case_info.device_product))
                        else:
                            if attach_eml_files:
                                attach_file_to_case(case_info, eml_attachments, connector_scope.LOGGER)
                                attach_file_to_case(case_info, msg_attachments, connector_scope.LOGGER)
                            # Ingest the case to siemplify
                            cases.append(case_info)

                    except Exception as e:
                        connector_scope.LOGGER.error("Failed to create CaseInfo")
                        connector_scope.LOGGER.exception(e)
                        if test_run:
                            raise
            except Exception as e:
                connector_scope.LOGGER.error(
                    "Failed to process email with message_id={0}".format(original_msg.message_id))
                connector_scope.LOGGER.exception(e)
                if test_run:
                    raise

        if not test_run:
            connector_scope.LOGGER.info("Saving existing ids.")
            write_ids(connector_scope, existing_ids, stored_ids_limit=STORED_IDS_LIMIT)
            # Convert to EWStime to str in order to convert to datetime
            new_last_exe_datetime = convert_string_to_datetime(new_last_exe_time.isoformat())
            connector_scope.save_timestamp(datetime_format=True,
                                           new_timestamp=new_last_exe_datetime)

            connector_scope.LOGGER.info("Created {} cases.".format(len(cases)))

    except Exception as error:
        connector_scope.LOGGER.error("Error in main handler")
        connector_scope.LOGGER.exception(error)
        if test_run:
            raise error

    connector_scope.LOGGER.info("------------------- Main - Finished -------------------")
    connector_scope.return_package(cases)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        main(test_run=False)
    else:
        main(test_run=True)
