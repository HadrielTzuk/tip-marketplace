import os
import re
import sys
import uuid
from typing import List, Dict

from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import (
    is_overflowed,
    extract_connector_param,
    get_last_success_time,
    read_ids,
    write_ids,
    save_timestamp,
    convert_datetime_to_unix_time,
    is_approaching_timeout,
    unix_now,
    TIMEOUT_THRESHOLD
)

from EmailUtils import get_html_urls, EmailUtils
from MicrosoftGraphMailManager import MicrosoftGraphMailManager
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import CaseInfo
from SiemplifyUtils import output_handler
from constants import (
    CASE_NAME_PATTERN,
    DEFAULT_DIVIDER,
    PRIORITY_DEFAULT,
    STORED_IDS_LIMIT,
    KEYS_TO_EXCEPT_ON_TRANSFORMATION,
)
from datamodels import MicrosoftGraphEmail
from exceptions import InvalidParameterException
from utils import (
    transform_dict_keys,
    transform_template_string,
    create_siemplify_case_wall_attachment_object,
)

# =====================================
#              CONSTANTS              #
# =====================================
CONNECTOR_NAME = "Microsoft Graph Mail Connector"
CONNECTOR_STARTING_TIME = unix_now()


class GraphToSiemplifyService:
    def __init__(self, siemplify, environment_common, alert_per_attachment: bool, case_name_template: str,
                 alert_name_template: str, headers_to_add_to_events: List[str]):
        self.siemplify = siemplify
        self.environment_common = environment_common
        self.alert_per_attachment = alert_per_attachment
        self.case_name_template = case_name_template
        self.alert_name_template = alert_name_template
        self.headers_to_add_to_events = headers_to_add_to_events
        self.regex_map = self.build_regex_map(self.siemplify.whitelist)
        self.email_utils = EmailUtils()

    def build_regex_map(self, regex_list):
        regex_map = {}
        for regex_item in regex_list:
            try:
                if ': ' in regex_item:
                    # Split only once by ':'
                    user_regex = regex_item.split(': ', 1)
                    # check if user regex include key (regex name) and value (the regex itself)
                    if len(user_regex) >= 2:
                        regex_map.update({user_regex[0]: user_regex[1]})
            except Exception as e:
                self.siemplify.logger.error(
                    "Unable to get parse whitelist item {}. Ignoring item and continuing.".format(
                        regex_item))
                self.siemplify.logger.exception(e)
        return regex_map

    def extract_regex_from_content(self, email_subject, email_body):
        """
        Get urls, subject, from and to addresses from email body
        :param email_subject: {str} email subject
        :param email_body: {str} email body
        :return: {dict} fields after parse.
        """

        result_dictionary = {}
        for key, regex_value in self.regex_map.items():
            if regex_value:
                regex_object = re.compile(regex_value)
                all_results = (
                    regex_object.findall(email_body) +
                    regex_object.findall(email_subject)
                )

                for index, result in enumerate(all_results, 1):
                    # Divide keys
                    key_name = f'{key}_{index}'
                    result_dictionary[key_name] = result

        return result_dictionary

    def get_eml_attachments(self, email: MicrosoftGraphEmail):
        """
        Get eml attachments.
        :param email: {MicrosoftGraphEmail} Parse microsoft graph email
        :return: {list} EML attachments list exported from original message
        """
        attachments = []

        for eml_attachment in email.eml_attachments:
            try:
                self.siemplify.LOGGER.info("Parsing EML: {}".format(eml_attachment.name))
                parsed_eml = self.email_utils.convert_siemplify_eml_to_connector_eml(
                    eml_attachment.content, headers_to_add=self.headers_to_add_to_events)
                parsed_eml["attachments_md5_filehash"] = eml_attachment.md5_hash()

                attachments.append((eml_attachment.name, parsed_eml))

            except Exception as err:
                self.siemplify.LOGGER.error("Failed Parsing EML content")
                self.siemplify.LOGGER.exception(err)
        return attachments

    def get_msg_attachments(self, email: MicrosoftGraphEmail):
        """
        Get msg attachments.
        :param email: {MicrosoftGraphEmail} Parse microsoft graph email
        :return: {list} MSG attachments list exported from original message
        """
        parsed_attachments = []
        for msg_attachment in email.msg_attachments:
            try:
                self.siemplify.LOGGER.info("Parsing MSG: {}".format(msg_attachment.name))
                parsed_msg = self.email_utils.convert_siemplify_msg_to_connector_msg(
                    msg_attachment.content)
                parsed_msg["attachments_md5_filehash"] = msg_attachment.md5_hash()

                parsed_attachments.append((msg_attachment.name, parsed_msg))

            except Exception as err:
                self.siemplify.LOGGER.error("Failed Parsing MSG content")
                self.siemplify.LOGGER.exception(err)

        return parsed_attachments

    def get_ics_attachments(self, email: MicrosoftGraphEmail):
        """
        Get ics attachments.
        :param email: {MicrosoftGraphEmail} Parse microsoft graph email
        :return: {email} ICS attachments list exported from original message
        """
        parsed_attachments_data = []
        for ics_attachment in email.ics_attachments:
            try:
                self.siemplify.LOGGER.info("Parsing ICS: {}".format(ics_attachment.name))
                parsed_ics_list = self.email_utils.convert_siemplify_ics_to_connector_msg(
                    ics_attachment.content)

                if len(parsed_ics_list) > 1:
                    file_name, file_extension = os.path.splitext(ics_attachment.name)
                    for index, ics in enumerate(parsed_ics_list, 1):
                        new_file_name = "{}_{}{}".format(file_name, index, file_extension)
                        parsed_attachments_data.append((new_file_name, ics))
                elif len(parsed_ics_list) == 1:
                    parsed_attachments_data.append((ics_attachment.name, parsed_ics_list[0]))

            except Exception as err:
                self.siemplify.LOGGER.error("Failed Parsing ICS content")
                self.siemplify.LOGGER.exception(err)

        return parsed_attachments_data

    def attach_file_to_case(self, file_name, file_content):
        self.siemplify.LOGGER.info("Checking EML and MSG attachments to attach to the case")

        try:
            if isinstance(file_content, str):
                file_content = file_content.encode()
            self.siemplify.LOGGER.info("Attached {} file to the case".format(file_name))
            return create_siemplify_case_wall_attachment_object(file_name, file_content)
        except Exception as e:
            self.siemplify.LOGGER.error("Failed to attach {} to the case wall".format(file_name))
            self.siemplify.LOGGER.exception(e)

    def process_alert(self, alert: MicrosoftGraphEmail, attached_mail_prefix: str, original_mail_prefix: str):
        if not self.alert_per_attachment:
            return [self.create_case(alert, attached_mail_prefix, original_mail_prefix), ]
        return self.create_cases(alert, attached_mail_prefix, original_mail_prefix)

    def get_item_attachments_data(self, email):
        """
        Get attachments from message.
        :param email: {MicrosoftGraphEmail} If True will load only unread emails.
        :return: {list} Item attachments list exported from original message
        """
        eml_attachments = self.get_eml_attachments(email)
        msg_attachments = self.get_msg_attachments(email)
        ics_attachments = self.get_ics_attachments(email)

        self.siemplify.LOGGER.info(
            'Found {0} EMLs, {1} MSGs and {2} ICSs for mail with ID: {3}'.format(
                len(eml_attachments),
                len(msg_attachments),
                len(ics_attachments),
                email.id))

        return eml_attachments + msg_attachments + ics_attachments

    def get_events_for_attachments(self, alert: MicrosoftGraphEmail, prefix=None):
        """
        Create and return evens from original message attachments only EML/MSG/ICS.
        :param alert: {MicrosoftGraphEmail} Parsed EML content.
        :param prefix: {str} Prefix for events keys
        :return: list , list events: Events list created from attachments, file_names:
        list of file names only EML/MSG/ICS
        """
        events = []
        attachments = self.get_item_attachments_data(alert)
        for index, value in enumerate(attachments):
            parsed_email_filename, parsed_email = value
            self.siemplify.LOGGER.info("Processing parsed email: {}".format(parsed_email_filename))
            parsed_email_body = parsed_email["body"]["content"] or ""
            parsed_email_subject = parsed_email["subject"] or ""

            additional_info = self.extract_regex_from_content(
                email_subject=parsed_email_subject,
                email_body=parsed_email_body
            )

            urls, original_src_urls = get_html_urls(parsed_email_body)
            additional_info.update({"urls_from_html_part": original_src_urls})
            additional_info.update({"visible_urls_from_html_part": urls})

            event_data = alert.create_event(
                additional_info=additional_info,
                attachment_data=parsed_email,
            )
            event_data = transform_dict_keys(
                original_dict=event_data,
                prefix=prefix,
                suffix=index,
                keys_to_except=KEYS_TO_EXCEPT_ON_TRANSFORMATION
            )

            events.append(event_data)
        return events

    def create_case(self, alert: MicrosoftGraphEmail, attached_mail_prefix, original_mail_prefix):
        attachment_events = self.get_events_for_attachments(alert, attached_mail_prefix)
        case_info = self.generate_case_info(alert=alert, mail_prefix=original_mail_prefix)
        case_info.events.extend(attachment_events)
        return case_info

    def create_cases(self, alert, attached_mail_prefix, original_mail_prefix):
        case_info = self.generate_case_info(alert=alert, mail_prefix=original_mail_prefix)
        cases = [case_info, ]
        item_attachments = self.get_item_attachments_data(alert)
        for attachment_name, attachment_data in item_attachments:
            attachment_case = self.generate_case_info(
                alert=alert,
                mail_prefix=attached_mail_prefix,
                attachment_data=attachment_data,
            )
            attachment_case.events.append(case_info.events[0])
            cases.append(attachment_case)
        return cases

    def generate_case_info(self, alert: MicrosoftGraphEmail, mail_prefix, attachment_data: Dict = None):
        additional_info = self.extract_regex_from_content(
            email_subject=alert.subject,
            email_body=alert.body_content
        )
        urls, original_src_urls = get_html_urls(alert.body_content)
        additional_info.update({"urls_from_html_part": original_src_urls})
        additional_info.update({"visible_urls_from_html_part": urls})

        event_details = alert.create_event(additional_info=additional_info,
                                           attachment_data=attachment_data,
                                           headers_to_add_to_events=self.headers_to_add_to_events)
        self.siemplify.LOGGER.info("Event dict created.")

        # Construct case name if case name template provided
        case_name = transform_template_string(self.case_name_template, event_details)\
            if self.case_name_template else ""
        # Construct alert name if alert name template provided
        alert_name = transform_template_string(self.alert_name_template, event_details)\
            if self.alert_name_template else ""

        event_details = transform_dict_keys(
            original_dict=event_details,
            prefix=mail_prefix,
            keys_to_except=KEYS_TO_EXCEPT_ON_TRANSFORMATION
        )

        if case_name:
            event_details["custom_case_name"] = case_name

        # Create case info object
        case_info = CaseInfo()
        case_info.name = alert_name or CASE_NAME_PATTERN.format(alert.mailbox_name)
        case_info.rule_generator = case_info.name
        case_info.start_time = convert_datetime_to_unix_time(alert.parsed_time)
        case_info.end_time = convert_datetime_to_unix_time(alert.parsed_time)
        case_info.identifier = alert.internet_message_id
        case_info.ticket_id = case_info.identifier
        case_info.display_id = alert.id if attachment_data is None else str(uuid.uuid4())
        case_info.priority = PRIORITY_DEFAULT
        case_info.device_vendor = event_details["device_vendor"]
        case_info.device_product = event_details["device_product"]
        case_info.attachments = []

        if attachment_data is None:
            # append attachments to case wall
            for attachment in alert.file_attachments:
                attachment_for_case = self.attach_file_to_case(attachment.name, attachment.content)
                if attachment_for_case:
                    case_info.attachments.append(attachment_for_case)

        case_info.environment = self.environment_common.get_environment(event_details)
        case_info.events = [event_details]

        return case_info


@output_handler
def main(test_run):
    cases = []
    connector_scope = SiemplifyConnectorExecution()
    connector_scope.script_name = CONNECTOR_NAME

    if test_run:
        connector_scope.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    connector_scope.LOGGER.info("-------------------- Main - Param Init --------------------")

    environment_field_name = extract_connector_param(
        connector_scope,
        param_name="Environment Field Name"
    )
    environment_regex = extract_connector_param(
        connector_scope,
        param_name='Environment Regex Pattern'
    )
    script_timeout = extract_connector_param(
        connector_scope,
        param_name="PythonProcessTimeout",
        is_mandatory=True,
        input_type=int,
        print_value=True
    )

    # Account and connection
    azure_ad_endpoint = extract_connector_param(
        connector_scope,
        param_name='Azure AD Endpoint',
        is_mandatory=True
    )
    microsoft_graph_endpoint = extract_connector_param(
        connector_scope,
        param_name='Microsoft Graph Endpoint',
        is_mandatory=True
    )
    mail_address = extract_connector_param(
        connector_scope,
        param_name="Mail Address",
        is_mandatory=True
    )
    client_id = extract_connector_param(
        connector_scope,
        param_name='Client ID',
        input_type=str,
        is_mandatory=True,
    )
    client_secret = extract_connector_param(
        connector_scope,
        param_name='Client Secret',
        input_type=str,
        is_mandatory=True,
        remove_whitespaces=False
    )
    tenant = extract_connector_param(
        connector_scope,
        param_name='Tenant (Directory) ID',
        input_type=str,
        is_mandatory=True,
    )
    verify_ssl = extract_connector_param(
        connector_scope,
        param_name="Verify SSL",
        input_type=bool,
        is_mandatory=True
    )

    # Flow control for fetching
    folder_name = extract_connector_param(
        connector_scope,
        param_name="Folder to check for emails",
        is_mandatory=True
    )
    email_exclude_pattern = extract_connector_param(
        connector_scope,
        param_name='Email exclude pattern'
    )
    offset_time_in_hours = extract_connector_param(
        connector_scope,
        param_name="Offset Time In Hours",
        input_type=int,
        is_mandatory=True
    )
    max_email_per_cycle = extract_connector_param(
        connector_scope,
        param_name="Max Emails Per Cycle",
        input_type=int,
        is_mandatory=True
    )
    unread_only = extract_connector_param(
        connector_scope,
        param_name="Unread Emails Only",
        input_type=bool
    )
    disable_overflow = extract_connector_param(
        siemplify=connector_scope,
        param_name="Disable Overflow",
        input_type=bool
    )

    # Processing params
    mark_as_read = extract_connector_param(
        connector_scope,
        param_name="Mark Emails as Read",
        input_type=bool
    )
    original_mail_prefix = extract_connector_param(
        connector_scope,
        param_name="Original Received Mail Prefix"
    )
    attached_mail_prefix = extract_connector_param(
        connector_scope,
        param_name="Attached Mail File Prefix"
    )
    alert_per_attachment = extract_connector_param(
        connector_scope,
        param_name="Create a Separate Siemplify Alert per Attached Mail File",
        input_type=bool
    )
    headers_to_add_to_events = extract_connector_param(
        connector_scope,
        param_name='Headers to add to events'
    )
    case_name_template = extract_connector_param(
        connector_scope,
        param_name="Case Name Template"
    )
    alert_name_template = extract_connector_param(
        connector_scope,
        param_name="Alert Name Template"
    )

    # Parameters parsing and transformation
    headers_to_add_to_events = list(filter(
        lambda x: bool(x),
        map(lambda x: x.strip(),
            headers_to_add_to_events.split(DEFAULT_DIVIDER))
    )) if headers_to_add_to_events else []

    connector_scope.LOGGER.info("------------------- Main - Started -------------------")

    try:
        if original_mail_prefix and " " in original_mail_prefix:
            raise InvalidParameterException("Original Received Mail Prefix configured contains a space, which is not "
                                            "supported, please remove any spaces and try again.")

        if attached_mail_prefix and " " in attached_mail_prefix:
            raise InvalidParameterException("Attached Mail File Prefix configured contains a space, which is not "
                                            "supported, please remove any spaces and try again.")

        if offset_time_in_hours < 0:
            raise InvalidParameterException(f"\"Offset Time In Hours\" must be non-negative")

        # Read already existing email ids
        existing_ids = read_ids(connector_scope)
        connector_scope.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing ids")
        last_success_time = get_last_success_time(connector_scope, offset_with_metric={'hours': offset_time_in_hours})
        environment_common = GetEnvironmentCommonFactory.create_environment_manager(
            siemplify=connector_scope,
            environment_field_name=environment_field_name,
            environment_regex_pattern=environment_regex
        )

        connector_scope.LOGGER.info("Connecting to Microsoft Graph Mail.")
        email_client = MicrosoftGraphMailManager(
            azure_ad_endpoint=azure_ad_endpoint,
            microsoft_graph_endpoint=microsoft_graph_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            tenant=tenant,
            siemplify=connector_scope,
            mail_address=mail_address,
            verify_ssl=verify_ssl
        )

        emails_from_api = email_client.get_emails(
            folder_name=folder_name,
            datetime_from=last_success_time,
            max_email_per_cycle=max_email_per_cycle,
            existing_ids=existing_ids,
            unread_only=unread_only,
            email_exclude_pattern=email_exclude_pattern,
            connector_starting_time=CONNECTOR_STARTING_TIME,
            script_timeout=script_timeout
        )

        if test_run:
            emails_from_api = emails_from_api[:1]
            connector_scope.LOGGER.info("Trimmed number of emails for processing to 1, since it's a test run")

        processed_emails = []

        for email in emails_from_api:
            if is_approaching_timeout(script_timeout, CONNECTOR_STARTING_TIME, TIMEOUT_THRESHOLD):
                connector_scope.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                break

            connector_scope.LOGGER.info(f"Starting processing of {email.id}")

            graph_to_siemplify_service = GraphToSiemplifyService(
                siemplify=connector_scope,
                environment_common=environment_common,
                alert_per_attachment=alert_per_attachment,
                case_name_template=case_name_template,
                alert_name_template=alert_name_template,
                headers_to_add_to_events=headers_to_add_to_events
            )
            new_cases = graph_to_siemplify_service.process_alert(
                alert=email,
                attached_mail_prefix=attached_mail_prefix,
                original_mail_prefix=original_mail_prefix
            )
            original_case = new_cases[0]

            alert_is_overflowed = (
                not disable_overflow and
                is_overflowed(connector_scope, original_case, test_run)
            )
            if alert_is_overflowed:
                connector_scope.LOGGER.info(
                    f'{original_case.rule_generator}-{original_case.ticket_id}-'
                    f'{original_case.environment}-{original_case.device_product}'
                    f' found as overflow alert. Skipping.'
                )
                continue

            cases.extend(new_cases)
            processed_emails.append(email)
            existing_ids.append(email.id)

        if mark_as_read and not test_run:
            email_client.mark_emails_as_read(processed_emails)

        if not test_run and processed_emails:
            connector_scope.LOGGER.info("Saving existing ids.")
            write_ids(connector_scope, existing_ids, stored_ids_limit=STORED_IDS_LIMIT)
            save_timestamp(
                siemplify=connector_scope,
                alerts=processed_emails,
                timestamp_key="timestamp"
            )

        connector_scope.LOGGER.info("Created {} cases.".format(len(cases)))

    except InvalidParameterException as error:
        connector_scope.LOGGER.error(error)
        if test_run:
            raise error

        raise

    except Exception as error:
        connector_scope.LOGGER.error("Error in main handler")
        connector_scope.LOGGER.exception(error)
        if test_run:
            raise error

        raise

    connector_scope.LOGGER.info("------------------- Main - Finished -------------------")
    connector_scope.return_package(cases)


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test)
