from SiemplifyUtils import output_handler
# ============================================================================#
# title           :EmailConnector.py
# description     :This Module contain all Email connector functionality
# author          :zivh@siemplify.co
# date            :24-04-2018
# python_version  :2.7
# ============================================================================#

# ============================= IMPORTS ===================================== #
import sys
import re
import json
import uuid
import hashlib
import arrow
import copy
import base64
import os
from urlparse import urlparse
from SiemplifyDataModel import Attachment
from SiemplifyConnectors import CaseInfo, SiemplifyConnectorExecution
from EmailManager import EmailManager
from EmailCommon import EmailCommon, DEFAULT_REGEX_MAP, DEAFULT_SUBJECT_TEXT, FILE_NAME_EVENT_FIELD_PATTERN,\
    FILE_MD5_EVENT_FIELD_PATTERN, URLS_REGEX

# ============================== CONSTS ===================================== #
PRODUCT = VENDOR = "Mail"
DATE_TIME_STR_FORMAT = "%a, %d %b %Y %H:%M:%S %z"
DEFAULT_NAME = "Monitored Mailbox <{0}>"
TIMESTAMP = "timestamp.stmp"
FIRST_TIME_RUN_OFFSET_IN_DAYS = 5
MAX_EMAILS_PER_CYCLE = 10
ORIGINAL_MESSAGE_TYPE = '.eml'
EML_ATTACHMENT_DESCRIPTION = 'This is the original message as EML'
MSG_ID_ERROR_MSG = "Can't get message id"

URL_REGEX = {"urls": URLS_REGEX}

MAP_FILE = 'map.json'


# ============================= CLASSES ===================================== #
class EmailConnectorException(Exception):
    """
    Email Connector Exception
    """
    pass


class EmailConnector(object):
    def __init__(self, connector_scope, email_manager, unread_only, max_emails_per_cycle, server_time_zone, email_common):
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER
        self.email_manager = email_manager
        self.unread_only = unread_only
        self.max_emails_per_cycle = max_emails_per_cycle
        self.server_time_zone = server_time_zone
        self.map_file = os.path.join(self.connector_scope.run_folder, MAP_FILE)
        self.email_common = email_common

        try:
            if not os.path.exists(self.map_file):
                with open(self.map_file, 'w+') as map_file:
                    map_file.write(json.dumps(
                        {"Original environment name": "Desired environment name",
                         "Env1": "MyEnv1"}))
                    self.connector_scope.LOGGER.info(
                        "Mapping file was created at {}".format(unicode(self.map_file).encode("utf-8")))
        except Exception as e:
            self.logger.error("Unable to create mapping file: {}".format(str(e)))
            self.logger.exception(e)


    # Notice! This sets an HTTP proxy! This will work only above HTTP protocol!
    # If an IMAP protocol is used, an IMAP proxy is needed.
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

    def get_emails(self, last_run, attach_original_eml=False):
        """
        Get emails alerts.
        :param last_run: {datetime} last execution time from file
        :param attach_original_eml: {boolean} get the mail eml (in eml format)
        :return: {objects list} Messages Objects OR Json Containing all suitable mails

        """
        filtered_mails = []

        try:
            # last_run is in UTC, same as the mail time. Manger is validate the timezones.
            filtered_mails_ids = self.email_manager.receive_mail_ids(time_filter=last_run, only_unread=self.unread_only)

        except Exception as e:
            filtered_mails_ids = []
            self.logger.error("Failed to retrieve emails. Error message: {}".format(e.message))
            self.logger.exception(e)

        if filtered_mails_ids:

            for msg_id in filtered_mails_ids:
                try:
                    if attach_original_eml:
                        # Get also the original eml
                        mail_dict = self.email_manager.get_message_data_by_message_id(msg_id, include_raw_eml=True)
                    else:
                        mail_dict = self.email_manager.get_message_data_by_message_id(msg_id)

                    # Check if email is already taken, if yes - continue
                    if self.email_common.validate_email_time(last_run, mail_dict, self.server_time_zone):
                        continue

                    filtered_mails.append(mail_dict)
                    
                    # emails limit per cycle - Default - The 10 oldest emails.
                    if len(filtered_mails) == self.max_emails_per_cycle:
                        return filtered_mails
                except Exception as e:
                    self.logger.error("Failed to retrieve email data. Error message: {}".format(e.message))
                    self.logger.exception(e)

            self.logger.info("Found {} emails.".format(len(filtered_mails)))

        return filtered_mails

    def extract_urls_from_html_body(self, email_html_body, event_details):
        """
        Get urls from email html body (so links will also be captured)
        :param email_html_body: {dict} email original message
        :param event_details: {dict} event fields
        :return: {dict} updated fields after URL Parsing.
        """
        event_details.update(self.email_common.extract_event_details(email_html_body, URL_REGEX))

    def create_event(self, email, regex_map):
        """
        Create events from email data
        :param email: {dict} All email data
        :param regex_map: {dict}
        :return: event {dict} one event from the email data
        """
        event_details = {}

        if email.get('body'):
            event_details = self.email_common.extract_event_details(email['body'], regex_map)
            try:
                if email.get('html_body'):
                    # Extract only url from html
                    self.extract_urls_from_html_body(email['html_body'], event_details)
                else:
                    self.extract_urls_from_html_body(email['body'], event_details)
            except Exception as e:
                self.logger.error("Cannot process html body")
                self.logger.exception(e)

        # Handle fwd/not fwd
        # override all same regex keys in event_details, for mapping and modeling
        event_details = self.email_common.handle_fwd(email, event_details)

        # Email date is in UTC time, save time in unix.
        # * 1000 to convert unix time to millisecond.
        event_details['email_time'] = arrow.get(email.get('date', 1)).timestamp * 1000
        event_details['body'] = email.get('body', '')
        event_details['email_uid'] = email.get('email_uid')
        event_details['vendor'] = event_details['device_product'] = PRODUCT

        try:
            event_details['event_name'] = DEFAULT_NAME.format(self.email_manager.mail_address)
        except (IndexError, KeyError) as e:
            self.logger.error("Can't display the monitored mailbox for event name. {0}".format(e))
            event_details['event_name'] = DEFAULT_NAME

        try:
            event_details['message_id'] = email.get('message_id')
        except Exception as e:
            event_details['message_id'] = '{0}-{1}'.format(MSG_ID_ERROR_MSG, str(uuid.uuid4()))
            self.logger.error("Found mail, cannot get its message id. {0}".format(str(e)))

        try:
            attachments = self.get_email_attachments(email)
            event_details.update(attachments)
        except Exception as e:
            self.logger.error("An error occurred during extracting the attachments.")
            self.logger.exception(e)

        event_details["managerReceiptTime"] = event_details["StartTime"] = event_details["EndTime"] = event_details[
            "generated_time"] = event_details['email_time']

        return event_details

    def get_email_attachments(self, email):
        """
        get attachments data from mail
        :param email: {dict} All email data
        :return: {dict} attachments info - name and md5 hash
        """
        # Get attachment name and content from email
        attachments = self.email_manager.extract_attachments(email['email_uid'])

        # Arrange the attachments
        divided_attachments = {}
        self.logger.info("Found {0} attachments".format(len(attachments)))
        for index, (attachment_name, attachment_value) in enumerate(attachments.items(), 1):
            try:
                divided_attachments[FILE_NAME_EVENT_FIELD_PATTERN.format(index)] = attachment_name
                divided_attachments[FILE_MD5_EVENT_FIELD_PATTERN.format(index)] = hashlib.md5(
                    attachment_value).hexdigest()
                self.logger.info(u"Found attachment: {}".format(attachment_name))
            except Exception as e:
                self.logger.error("Cannot process attachment {0}".format(index))
                self.logger.exception(e)

        return divided_attachments

    @staticmethod
    def create_attachment_object(original_msg_content, attachment_name):
        """
        Create attachment object with the original email
        :param original_msg_content: {string} original message content
        :param attachment_name: {string} email subject as the attachment name
        :return: {Attachment} of attachment object
        """
        base64_blob = base64.b64encode(original_msg_content)
        attachment_object = Attachment(
            case_identifier=None, alert_identifier=None,
            base64_blob=base64_blob,
            attachment_type=ORIGINAL_MESSAGE_TYPE, name=attachment_name,
            description=EML_ATTACHMENT_DESCRIPTION,
            is_favorite=False, orig_size=len(original_msg_content),
            size=len(base64_blob))
        return attachment_object

    def create_case_info(self, email, event, environment_field_name, environment_regex, default_environment):
        """
        Get alerts from Email
        :param email: {dict} An email data
        :param event: {dict} one event from the email data
        :param environment_field_name: {str} The field name to extract environment from
        :param environment_regex: {str} The regex pattern to extract environment from the environment field
        :param default_environment: {str} The default environment to use
        :return: {CaseInfo} case
        """
        # Validate email message id exists
        try:
            email_id = email['message_id']
        except Exception as e:
            email_id = '{0}-{1}'.format(MSG_ID_ERROR_MSG, str(uuid.uuid4()))
            self.logger.error("Found mail, cannot get its message id. {0}".format(str(e)))

        case_info = CaseInfo()
        self.logger.info("Creating Case for Email {}".format(email_id))

        # Create the CaseInfo
        try:
            case_info.name = event.get("event_name", DEFAULT_NAME)
            case_info.rule_generator = event.get("event_name", DEFAULT_NAME)
            case_info.start_time = event.get("email_time", 1)
            case_info.end_time = event.get("email_time", 1)
            case_info.identifier = email_id
            case_info.ticket_id = case_info.identifier
            case_info.priority = 40  # Defaulting to Low.
            case_info.device_vendor = VENDOR
            case_info.device_product = PRODUCT
            case_info.display_id = case_info.identifier

            if environment_field_name and event.get(environment_field_name):
                # Get the environment from the given field
                environment = event.get(environment_field_name, "")

                if environment_regex:
                    # If regex pattern given - extract environment
                    match = re.search(environment_regex, environment)

                    if match:
                        # Get the first matching value to match the pattern
                        environment = match.group()

                # Try to resolve the found environment to its mapped alias.
                # If the found environment / extracted environment is empty
                # use the default environment
                case_info.environment = self.email_common.get_mapped_environment(
                    environment, self.map_file) if environment else default_environment

            else:
                case_info.environment = default_environment

            case_info.events = [event]

        except KeyError as e:
            raise KeyError(
                "Mandatory key is missing: {}. Skipping email.".format(unicode(e.message.encode('utf-8'))))

        return case_info


@output_handler
def main(is_test=False):
    """
    Main execution - Email Connector
    """
    connector_scope = SiemplifyConnectorExecution()
    output_variables = {}
    log_items = []

    connector_scope.LOGGER.info("=======Starting Email Connector.=======")

    try:
        from_address = connector_scope.parameters.get("Sender's address")
        imap_host = connector_scope.parameters.get('IMAP Server Address')
        imap_port = str(connector_scope.parameters['IMAP Port'])
        username = connector_scope.parameters.get('Username')
        password = connector_scope.parameters.get('Password')
        first_run_timestamp = int(
            connector_scope.parameters.get('Offset Time In Days', FIRST_TIME_RUN_OFFSET_IN_DAYS))
        max_emails_per_cycle = int(connector_scope.parameters.get('Max Emails Per Cycle', MAX_EMAILS_PER_CYCLE))

        use_ssl = connector_scope.parameters['IMAP USE SSL'].lower() == 'true'
        unread_only = connector_scope.parameters['Unread Emails Only'].lower() == 'true'
        mark_as_read = connector_scope.parameters['Mark Emails as Read'].lower() == 'true'
        server_time_zone = connector_scope.parameters.get('Server Time Zone', 'UTC')
        environment_field_name = connector_scope.parameters.get('Environment Field Name')
        environment_regex = connector_scope.parameters.get('Environment Regex Pattern')

        attach_original_eml = connector_scope.parameters.get('Attach Original EML').lower() == 'true'

        proxy_server = connector_scope.parameters.get('Proxy Server Address')
        proxy_username = connector_scope.parameters.get('Proxy Username')
        proxy_password = connector_scope.parameters.get('Proxy Password')

        email_common = EmailCommon(connector_scope.LOGGER)

        regex_map = email_common.build_regex_map(connector_scope.whitelist)

        # Try writing regex map to log
        try:
            connector_scope.LOGGER.info("The current regex map is: {}".format(str(regex_map)))
        except Exception as e:
            connector_scope.LOGGER.error("Error writing regex map to log")
            connector_scope.LOGGER.exception(e)
            if is_test:
                raise

        connector_scope.LOGGER.info("Connecting to Email manager")

        email_manager = EmailManager(
            from_address,
            proxy_server=proxy_server,
            proxy_username=proxy_username,
            proxy_password=proxy_password
        )
        email_common = EmailCommon(connector_scope.LOGGER)


        connector_scope.LOGGER.info("Login to IMAP")
        email_manager.login_imap(host=imap_host, port=imap_port, username=username, password=password,
                                 use_ssl=use_ssl)

        email_connector = EmailConnector(connector_scope, email_manager,
                                         unread_only, max_emails_per_cycle,
                                         server_time_zone, email_common)

        # Fix first time run
        last_run_time = connector_scope.fetch_timestamp(datetime_format=True)
        last_calculated_run_time = email_common.validate_timestamp(last_run_time, first_run_timestamp)
        connector_scope.LOGGER.info(
            "Calculating last run time. Last run time is: {0}".format(last_calculated_run_time))

        # Get alerts
        connector_scope.LOGGER.info("Collecting emails.")
        emails = email_connector.get_emails(last_calculated_run_time, attach_original_eml)

        # Test on one email only
        if is_test:
            emails = emails[:1]

        cases_to_ingest = []
        all_cases = []
        for email in emails:
            event = {}

            try:
                # Create security event
                event = email_connector.create_event(email, regex_map)
            except Exception as e:
                # If the event creation fails, event is an empty dict
                connector_scope.LOGGER.error("Failed to create event. {0}".format(str(e)))
                connector_scope.LOGGER.exception(e)

            try:
                # Create case info
                case = email_connector.create_case_info(
                    email,
                    event,
                    environment_field_name,
                    environment_regex,
                    connector_scope.context.connector_info.environment
                )

                # Attach original EML based on parameter
                if attach_original_eml:
                    try:
                        attachment_object = email_connector.create_attachment_object(email.get('original_message'), event['subject'])
                        # Add to case_info
                        case.attachments = [attachment_object]
                        connector_scope.LOGGER.info("Successfully attach original message as EML.")
                    except Exception as e:
                        connector_scope.LOGGER.error("Failed to attach original EML. Error: {0}.".format(e))

                is_overflow = False
                try:
                    # Check if alert overflow
                    is_overflow = connector_scope.is_overflowed_alert(
                        environment=case.environment,
                        alert_identifier=str(case.ticket_id),
                        alert_name=str(case.rule_generator),
                        product=str(case.device_product)
                    )
                except Exception as e:
                    connector_scope.LOGGER.error("Check if alert is overflow failed. Error: {0}.".format(e))

                if is_overflow:
                    # Skipping this alert (and dot ingest it to siemplify)
                    connector_scope.LOGGER.info(
                        "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping"
                            .format(alert_name=str(case.rule_generator),
                                    alert_identifier=str(case.ticket_id),
                                    environment=case.environment,
                                    product=str(case.device_product)))
                else:
                    # Ingest the case to siemplify
                    cases_to_ingest.append(case)
                all_cases.append(case)

                try:
                    # Mark specific email as read/unread because fetching emails automatically mark them as read.
                    # Mark the mail as read only if succeeded creating case.
                    email_manager.mark_email_as_read(email['email_uid'], mark_as_read)
                except Exception as e:
                    connector_scope.LOGGER.error(
                        "Failed to mark email as read. Error message: {}".format(e.message))
                    connector_scope.LOGGER.exception(e)
                    if is_test:
                        raise

            except Exception as e:
                connector_scope.LOGGER.error("Failed to create CaseInfo")
                connector_scope.LOGGER.error("Error Message: {}".format(e.message))
                connector_scope.LOGGER.exception(e)
                if is_test:
                    raise

        connector_scope.LOGGER.info("Completed processing emails.")

        # Get last successful execution time.
        if all_cases:
            # Sort the cases by the end time of each case.
            all_cases = sorted(all_cases, key=lambda case: case.end_time)
            # Last execution time is set to the newest message time
            new_last_run_time = all_cases[-1].end_time
        else:
            # last_calculated_run_time is datetime object. Convert it to milliseconds timestamp.
            new_last_run_time = arrow.get(last_calculated_run_time).timestamp * 1000

        connector_scope.LOGGER.info("Create {} cases.".format(len(cases_to_ingest)))
        connector_scope.LOGGER.info("=======Email Connector Finish.=======")

        if not is_test:
            # update last execution time
            connector_scope.save_timestamp(new_timestamp=new_last_run_time)
        # Return data
        connector_scope.return_package(cases_to_ingest, output_variables, log_items)

    except Exception as e:
        connector_scope.LOGGER.error(e.message)
        connector_scope.LOGGER.exception(e)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print "Main execution started"
        main()
    else:
        print "Test execution started"
        main(is_test=True)