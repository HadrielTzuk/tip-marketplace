import re
import os
import json
import sys
import hashlib
from base64 import b64encode
from SiemplifyUtils import output_handler
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import CaseInfo
from exchangelib import FileAttachment
from ExchangeManager import ExchangeManager
from ExchangeCommon import ExchangeCommon, FILE_NAME_EVENT_FIELD_PATTERN, FILE_MD5_EVENT_FIELD_PATTERN, \
    URL_EVENT_FIELD_PATTERN
from ExchangeConnectors import extract_connector_parameter, set_proxy, filter_emails_with_regexes
from SiemplifyUtils import convert_string_to_unix_time, utc_now, convert_string_to_datetime
from SiemplifyDataModel import Attachment
from TIPCommon import read_ids, write_ids, filter_old_alerts, is_overflowed
from EnvironmentCommon import GetEnvironmentCommonFactory
from constants import STORED_IDS_LIMIT, PRIORITY_DEFAULT

# =====================================
#              CONSTANTS              #
# =====================================
CONNECTOR_NAME = "Exchange Mail Connector"
ORIGINAL_MESSAGE_TYPE = ".eml"
EML_ATTACHMENT_DESCRIPTION = "This is the original message as EML"
DEVICE_PRODUCT = "Exchange"
VENDOR = "Microsoft"
EVENT_MAPPING_FIELD = "Exchange Mail Connector Mail Received"
CASE_NAME_PATTERN = "Monitored Mailbox <{0}>"
DEFAULT_DIVIDER = ","
URLS_DIVIDER = ";"
EMPTY_LINE = ""
UNDEFINED_MESSAGE_ID = "Cannot get message identifier"
UNDEFINED_NAME = 'Error getting name'


class ExchangeConnector(object):
    def __init__(self, connector_scope, exchange_manager, exchange_common):
        self.exchange_manager = exchange_manager
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER
        self.exchange_common = exchange_common

    def convert_msg_to_event(self, msg, regex_map):
        self.logger.info("Processing email with subject: {}".format(msg.subject))
        event_details = {}
        body = msg.text_body or msg.unique_body or EMPTY_LINE
        try:
            event_details = self.exchange_common.extract_regex_from_content(body, regex_map)
        except Exception as e:
            self.logger.error(
                "Could not extract data from mail body using regex executor, {}".format(e))
            self.logger.exception(e)

        # handle fw
        event_details = self.exchange_common.handle_fwd(msg, event_details, self.exchange_manager)

        # Add additional fields
        event_details['message_id'] = msg.message_id or UNDEFINED_MESSAGE_ID
        event_details['domain'] = self.exchange_manager.account.domain or EMPTY_LINE
        event_details['device_product'] = DEVICE_PRODUCT
        event_details['body'] = body
        event_details['name'] = CASE_NAME_PATTERN.format(
            self.exchange_manager.account.primary_smtp_address or EMPTY_LINE)
        event_details['device_vendor'] = VENDOR
        event_details['siemplify_event_mapping_field'] = EVENT_MAPPING_FIELD
        # Convert datetime to string in order convert EWSDateTime object into milliseconds
        str_time = (msg.datetime_created or utc_now()).isoformat()
        event_details['time'] = convert_string_to_unix_time(str_time)
        # This section is for legacy mapping rules
        event_details['StartTime'] = event_details['EndTime'] = event_details['time']

        self.logger.info("getting attachments.")
        # Add attachments
        hashes = []
        try:
            for i, attachment in enumerate(msg.attachments):
                try:
                    if isinstance(attachment, FileAttachment):
                        try:
                            self.logger.info("Found attachment: {}".format(attachment.name))
                        except:
                            self.logger.info("Found attachment, cannot log its name")
                        event_details[FILE_NAME_EVENT_FIELD_PATTERN.format(i + 1)] = attachment.name
                        event_details[FILE_MD5_EVENT_FIELD_PATTERN.format(i + 1)] = hashlib.md5(
                            attachment.content).hexdigest()
                        hashes.append(hashlib.md5(attachment.content).hexdigest())
                except Exception as e:
                    self.logger.error("Failed to handle msg attachment {}, {}".format(i, e))
            self.logger.info("Found {} attachments.".format(len(hashes)))
            try:
                event_details['files_hashes'] = DEFAULT_DIVIDER.join(hashes) if hashes else EMPTY_LINE
            except Exception as e:
                self.logger.error("Could not create the list of files hashes, {}".format(e))
        except Exception as e:
            self.logger.error("Could not fetch msg attachments, {}".format(e))

        # Separate urls to different fields
        try:
            if event_details.get('urls'):
                for index, url in enumerate(event_details['urls'].split(URLS_DIVIDER)):
                    try:
                        event_details[URL_EVENT_FIELD_PATTERN.format(index + 1)] = url
                    except Exception as e:
                        self.logger.error("Failed to detach url {}, {}".format(index, e))
        except Exception as e:
            self.logger.error("Failed to split urls from msg body {}".format(e))

        return event_details

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

    def create_case_from_message(
            self,
            msg,
            regex_map,
            mark_as_read,
            common_environment):

        event_details = self.convert_msg_to_event(msg, regex_map)
        self.logger.info("Event dict created.")

        # Create case info object
        case_info = CaseInfo()
        case_info.name = event_details.get('name', UNDEFINED_NAME)
        case_info.rule_generator = case_info.name
        case_info.start_time = event_details.get("time", 1)
        case_info.end_time = case_info.start_time
        case_info.identifier = msg.message_id or UNDEFINED_MESSAGE_ID
        case_info.ticket_id = case_info.identifier
        case_info.display_id = case_info.identifier
        case_info.priority = PRIORITY_DEFAULT  # Defaulting to Low - can add logic here to set priority based on event data.
        case_info.device_vendor = VENDOR
        case_info.device_product = DEVICE_PRODUCT
        case_info.environment = common_environment.get_environment(event_details)
        case_info.events = [event_details]

        # Try mark the message as read
        if mark_as_read:
            try:
                msg.is_read = True
                msg.save()
            except Exception as e:
                self.logger.error("Cannot mark the msg-{} as read, {}".format(case_info.identifier, e))
            self.logger.info("Marked msg as read")

        self.logger.info("Case Info created.")
        return case_info


# TODO: Replace this method with a common one from ExchangeConnectors
# Historically Exchange Mail Connector has parameter Server Ip, where as Exchange EML Connector - Server IP
# Thus to avoid regressive changes, there is a need to overwrite standard method for the manager initialization here
def init_manager(connector_scope):
    """
    Extracts all required parameters and initiates an ExchangeManager
    :param connector_scope: {SiemplifyConnectorExecution} Instance of the SiemplifyConnectorExecution representing connector scope
    :return: {ExchangeManager} ExchangeManager instance
    """
    server_ip = extract_connector_parameter(siemplify=connector_scope, param_name="Server Ip", is_mandatory=True)
    domain = extract_connector_parameter(siemplify=connector_scope, param_name="Domain", is_mandatory=True)
    username = extract_connector_parameter(siemplify=connector_scope, param_name="Username", is_mandatory=True)
    password = extract_connector_parameter(siemplify=connector_scope, param_name="Password", is_mandatory=True)
    mail_address = extract_connector_parameter(siemplify=connector_scope, param_name="Mail Address", is_mandatory=True)

    use_domain_in_auth = extract_connector_parameter(siemplify=connector_scope,
                                                     param_name="Use Domain For Authentication", input_type=bool,
                                                     default_value=True)
    verify_ssl = extract_connector_parameter(siemplify=connector_scope, param_name="Verify SSL", input_type=bool,
                                             default_value=False)

    return ExchangeManager(
        exchange_server_ip=server_ip,
        domain=domain,
        username=username,
        password=password,
        user_mail_address=mail_address,
        siemplify_logger=connector_scope.LOGGER,
        use_domain_in_auth=use_domain_in_auth,
        verify_ssl=verify_ssl
    )


@output_handler
def main(test_run=False):
    cases = []
    connector_scope = SiemplifyConnectorExecution()
    connector_scope.script_name = CONNECTOR_NAME

    if test_run:
        connector_scope.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    connector_scope.LOGGER.info("==================== Main - Param Init ====================")

    folder_name = extract_connector_parameter(siemplify=connector_scope, param_name="Folder Name",
                                              default_value="Inbox")
    environment_field_name = extract_connector_parameter(siemplify=connector_scope, param_name="Environment Field Name")
    environment_regex = extract_connector_parameter(siemplify=connector_scope, param_name="Environment Regex Pattern")
    unread_only = extract_connector_parameter(siemplify=connector_scope, param_name="Unread Emails Only",
                                              is_mandatory=True, input_type=bool)
    mark_as_read = extract_connector_parameter(siemplify=connector_scope, param_name="Mark Emails as Read",
                                               is_mandatory=True, input_type=bool)
    attach_original_eml = extract_connector_parameter(siemplify=connector_scope, param_name="Attach Original EML",
                                                      is_mandatory=True, input_type=bool)
    max_days_backwards = extract_connector_parameter(siemplify=connector_scope, param_name="Max Days Backwards",
                                                     is_mandatory=True, input_type=int)
    subject_exclude_regex = extract_connector_parameter(siemplify=connector_scope, param_name="Exclusion Subject Regex")
    body_exclude_regex = extract_connector_parameter(siemplify=connector_scope, param_name="Exclusion Body Regex")

    set_proxy(connector_scope)

    connector_scope.LOGGER.info("Connecting to Exchange.")
    email_client = init_manager(connector_scope)
    email_common = ExchangeCommon(connector_scope.LOGGER, email_client)
    exchange_connector = ExchangeConnector(connector_scope, email_client, email_common)
    common_environment = GetEnvironmentCommonFactory.create_environment_manager(
        connector_scope, environment_field_name, environment_regex
    )

    connector_scope.LOGGER.info("------------------- Main - Started -------------------")
    try:
        last_run = email_common.validate_max_days_backwards(
            connector_scope.fetch_timestamp(datetime_format=True),
            max_days_backwards
        )
        connector_scope.LOGGER.info("Last run time: {}".format(last_run))

        regex_map = email_common.build_regex_map(connector_scope.whitelist)
        connector_scope.LOGGER.info("Loaded regex_map: {}".format(regex_map))

        # Read already existing alerts ids
        existing_ids = read_ids(connector_scope)
        connector_scope.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing ids")

        emails = email_client.receive_mail(time_filter=last_run, only_unread=unread_only, folder_name=folder_name)
        emails = filter_old_alerts(connector_scope, emails, existing_ids, "message_id")

        connector_scope.LOGGER.info(
            "Found {0} emails with time_filter={1}, only_unread={2}, folder_name={3}".format(
                len(emails),
                last_run,
                unread_only,
                folder_name
            ))

        emails = filter_emails_with_regexes(emails, subject_exclude_regex, body_exclude_regex)
        connector_scope.LOGGER.info("Number of emails after filtering by regexes {}".format(len(emails)))

        # Last execution time is set to the newest message time
        new_last_exe_time = emails[0].datetime_received if emails else last_run
        connector_scope.LOGGER.info("Identified new timestamp to be set as a last_run: {}".format(new_last_exe_time))

        if test_run:
            emails = emails[:1]
            connector_scope.LOGGER.info("Trimmed number of emails for processing to 1, since it's a test run")

        connector_scope.LOGGER.info("Fetching emails according to timestamp.")
        for msg in emails:
            try:
                is_overflow = False
                case_info = exchange_connector.create_case_from_message(
                    msg=msg,
                    regex_map=regex_map,
                    mark_as_read=mark_as_read,
                    common_environment=common_environment
                )

                # Attach original EML based on parameter
                if attach_original_eml:
                    try:
                        attachment_object = exchange_connector.create_attachment_object(
                            msg.mime_content,
                            case_info.events[0]['subject'])
                        # Add to case_info
                        case_info.attachments = [attachment_object]
                        connector_scope.LOGGER.info("Successfully attached original message as EML.")
                    except Exception as e:
                        connector_scope.LOGGER.error("Failed to attach original EML. Error: {0}.".format(e))

                # Update existing alerts
                existing_ids.append(msg.message_id)

                # Check if alert overflow

                if is_overflowed(connector_scope, case_info, test_run):
                    # Skipping this alert (and dot ingest it to siemplify)
                    connector_scope.LOGGER.info(
                        "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.".format(
                            alert_name=case_info.rule_generator,
                            alert_identifier=case_info.ticket_id,
                            environment=case_info.environment,
                            product=case_info.device_product))
                else:
                    # Ingest the case to siemplify
                    cases.append(case_info)

            except Exception as e:
                connector_scope.LOGGER.error("An error occurred. Skipping email. {}".format(msg.message_id))
                connector_scope.LOGGER.exception(e)
                if test_run:
                    raise

        if test_run:
            connector_scope.LOGGER.info("Found {} emails.".format(len(emails)))
        else:
            connector_scope.LOGGER.info("Saving existing ids.")
            write_ids(connector_scope, existing_ids, stored_ids_limit=STORED_IDS_LIMIT)
            # Convert to EWStime to str in order to convert to datetime
            new_last_exe_datetime = convert_string_to_datetime(new_last_exe_time.isoformat())
            connector_scope.save_timestamp(datetime_format=True,
                                           new_timestamp=new_last_exe_datetime)

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
