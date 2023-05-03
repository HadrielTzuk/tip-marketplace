from SiemplifyUtils import output_handler
# ============================================================================#
# title           :EmailEMLConnector.py
# description     :This Module contain all Email connector functionality
# author          :zivh@siemplify.co
# date            :06-12-2018
# python_version  :2.7
# ============================================================================#

# ============================= IMPORTS ===================================== #
import json
import os
import sys
import re
import email
import datetime
import arrow
import copy
from urlparse import urlparse
from SiemplifyUtils import utc_now, dict_to_flat, convert_string_to_unix_time, \
    convert_datetime_to_unix_time
from SiemplifyConnectors import CaseInfo, SiemplifyConnectorExecution
from EmailManager import EmailManager, SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY
from EmailCommon import EmailCommon, DEFAULT_REGEX_MAP, DEAFULT_SUBJECT_TEXT, URLS_REGEX
from EmailStringUtils import safe_str_cast
# ============================== CONSTS ===================================== #
PRODUCT = VENDOR = "Mail EML"
DEFAULT_TIME_FORMAT = '%a, %d %b %Y %X'
EML_DATE_KEY = "Date"
EML_SUBJECT_KEY = "subject"
FIRST_TIME_RUN_OFFSET_IN_DAYS = 5
MAX_EMAILS_PER_CYCLE = 10
ORIGINAL_MESSAGE_TYPE = 'eml'
URL_REGEX = {
    "urls": URLS_REGEX}
MAP_FILE = 'map.json'

SIEMPLIFY_EML_TIME_KEY = "eml_time"
SIEMPLIFY_ORIGINAL_EMAIL_TIME_KEY = "email_time"

# ============================= CLASSES ===================================== #

class EmailEMLConnector(object):
    def __init__(self, connector_scope, email_manager, unread_only, max_emails_per_cycle, server_time_zone,
                 email_common):
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


    @staticmethod
    def set_proxy(proxy_server_address, proxy_username=None,
                  proxy_password=None):
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

        os.environ[
            'http_proxy'] = proxy_str  # http://<user>:<pass>@<proxy>:<port>
        os.environ[
            'https_proxy'] = proxy_str  # https://<user>:<pass>@<proxy>:<port>
        os.environ['proxy'] = "on"

    def get_emails(self, last_run):
        """
        Get emails alerts.
        :param last_run: {datetime} last execution time from file
        :return: {objects list} Messages Objects OR Json Containing all suitable mails

        """
        mails_ids = []

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
                    mail_dict = self.email_manager.get_message_data_by_message_id(msg_id)
                    # Check if email is already taken, if yes - continue
                    if self.email_common.validate_email_time(last_run, mail_dict, self.server_time_zone):
                        continue
                    mails_ids.append(msg_id)
                    # emails limit per cycle - Default - The 10 oldest emails.
                    if len(mails_ids) == self.max_emails_per_cycle:
                        return mails_ids
                except Exception as e:
                    self.logger.error("Failed to retrieve email data. Error message: {}".format(e.message))
                    self.logger.exception(e)

            self.logger.info("Found {0} emails. IDs: {1}".format(len(mails_ids), mails_ids))
        return mails_ids

    @staticmethod
    def fetch_eml_contents_from_attachments(attachments_dict):
        """
        Fetch all EMLs content from attachments dict.
        :param attachments_dict: {dict} Attachments dicts.
        :return: {dict} The dict of EML names and contents.
        """
        emls = {}
        for file_name, file_content in attachments_dict.items():
            if file_name.split('.')[-1].lower() == ORIGINAL_MESSAGE_TYPE:
                emls[file_name] = file_content
        return emls

    @staticmethod
    def string_with_postfix_to_datetime(time_string):
        """
        Will get rid of the time string postfix which is cause problem converting to datetime.
        :param time_string: {string} Time string
        :return: {datetime} Datetime object.
        """
        cover = len(datetime.datetime.now().strftime(DEFAULT_TIME_FORMAT))
        unaware = datetime.datetime.strptime(time_string[:cover], DEFAULT_TIME_FORMAT)
        return arrow.get(unaware).timestamp * 1000

    def create_event(self, email_id, parsed_eml):
        """
        Create event
        :param email_id: {dict} An email data
        :param parsed_eml: {dict}The parsed eml data.
        :return: {dict} EML content.
        """
        # Get the original email data
        mail_dict = self.email_manager.get_message_data_by_message_id(email_id)
        try:
            parsed_eml[SIEMPLIFY_ORIGINAL_EMAIL_TIME_KEY] = mail_dict.get(SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY, 1)
        except Exception as err:
            parsed_eml[SIEMPLIFY_ORIGINAL_EMAIL_TIME_KEY] = 1
            error_message = "Failed to fetch original email time for mail with ID: {0}".format(email_id)
            self.logger.error(error_message)
            self.logger.exception(err)

        try:
            eml_time = parsed_eml.get(SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY, 1)
        except Exception as err:
            error_message = "Failed to fetch eml time for mail with ID: {0}".format(email_id)
            self.logger.error(error_message)
            self.logger.exception(err)
            eml_time = 1

        parsed_eml[SIEMPLIFY_EML_TIME_KEY] = eml_time

        # Flatten the event
        flat_eml = dict_to_flat(parsed_eml)
        return flat_eml

    def create_case_info(self, email_id, event, environment_field_name, environment_regex, default_environment):
        """
        Get alerts from Email
        :param email_id: {dict} An email data
        :param event: {dict} Raw EML content.
        :param environment_field_name: {str} The field name to extract environment from
        :param environment_regex: {str} The regex pattern to extract environment from the environment field
        :param default_environment: {str} The default environment to use
        :return: {CaseInfo} case
        """
        case_info = CaseInfo()
        self.logger.info("Creating Case for Email {}".format(email_id))
        # Create the CaseInfo
        try:
            case_info.name = event.get(EML_SUBJECT_KEY, DEAFULT_SUBJECT_TEXT)
            case_info.rule_generator = case_info.name
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
            # Case times are the email time
            case_info.start_time = case_info.end_time = event.get(SIEMPLIFY_EML_TIME_KEY, 1)

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

    connector_scope.LOGGER.info("=======Starting Email EML Connector.=======")

    try:
        from_address = connector_scope.parameters.get("Mail address")
        imap_host = connector_scope.parameters.get('IMAP Server Address')
        imap_port = int(connector_scope.parameters.get('IMAP Port', 993))
        username = connector_scope.parameters.get('Username')
        password = connector_scope.parameters.get('Password')
        first_run_timestamp = int(
            connector_scope.parameters.get('Offset Time In Days', FIRST_TIME_RUN_OFFSET_IN_DAYS))
        max_emails_per_cycle = int(connector_scope.parameters.get('Max Emails Per Cycle', MAX_EMAILS_PER_CYCLE))
        use_ssl = connector_scope.parameters['IMAP USE SSL'].lower() == 'true'
        unread_only = connector_scope.parameters['Fetch Only Unread'].lower() == 'true'
        encode_utf8 = connector_scope.parameters.get('Encode Data as UTF-8', 'true').lower() == 'true'
        server_time_zone = connector_scope.parameters.get('Server Time Zone', 'UTC')
        environment_field_name = connector_scope.parameters.get(
            'Environment Field Name')
        environment_regex = connector_scope.parameters.get(
            'Environment Regex Pattern')

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

        connector_scope.LOGGER.info("Connecting to Email Manager")

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

        eml_connector = EmailEMLConnector(connector_scope, email_manager, unread_only, max_emails_per_cycle,
                                          server_time_zone, email_common)

        # Fix first time run
        last_run_time = connector_scope.fetch_timestamp(datetime_format=True)
        last_calculated_run_time = email_common.validate_timestamp(last_run_time, first_run_timestamp)
        connector_scope.LOGGER.info(
            "Calculating last run time. Last run time is: {0}".format(last_calculated_run_time))

        # Get alerts
        connector_scope.LOGGER.info("Collecting emails.")
        emails_ids = eml_connector.get_emails(last_calculated_run_time)

        # Test on one email only
        if is_test:
            emails_ids = emails_ids[:1]

        cases_to_ingest = []
        all_cases = []
        original_emails = []

        for email_id in emails_ids:
            try:
                mail_dict = email_manager.get_message_data_by_message_id(email_id)
                original_emails.append(mail_dict)

                mail_attachments = email_manager.extract_attachments(email_id, encode_as_base64=False,
                                                                     convert_utf8=encode_utf8)
                connector_scope.LOGGER.info(
                    'Running on mail with ID:{0}.'.format(email_id))

                attachments_emls = eml_connector.fetch_eml_contents_from_attachments(mail_attachments)
                connector_scope.LOGGER.info(
                    'Found {0} EMLs for mail with ID: {1}'.format(len(attachments_emls.keys()), email_id))

            except Exception as e:
                # If fetching emls files fails, attachments_emls is an empty list
                connector_scope.LOGGER.error("Failed to fetch EMLs for mail with ID:{0}".format(email_id))
                connector_scope.LOGGER.exception(e)
                attachments_emls = []

            for eml_filename, eml_content in attachments_emls.items():
                try:
                    # safe_str_cast to utf8 to align all the filenames, and then tries to decode the name as utf-8
                    # and encode it back as utf8 (as SiemplifyLogger might fail writing utf-8 strings to the logging file).
                    # If it will fail, then the encoding is not utf8 and we cannot guess it - write a default value to the log
                    # specifying te error.
                    connector_scope.LOGGER.info(u"Processing EML: {}".format(safe_str_cast(
                        eml_filename,
                        default_value="Unable to decode EML filename. Unknown encoding."
                    ).decode("utf-8")))

                    # Extract the data of the EML
                    parsed_eml = email_manager.parse_eml(eml_content, convert_body_to_utf8=encode_utf8,
                                                         convert_subject_to_utf8=encode_utf8,
                                                         encode_attachments_as_base64=True,
                                                         convert_filenames_to_utf8=encode_utf8)
                    try:
                        # Extract user regex from eml
                        connector_scope.LOGGER.info("Extracting user regex patterns from EML body")
                        extract_user_regex = email_common.extract_event_details(parsed_eml.get("body", ""), regex_map)

                        connector_scope.LOGGER.info("Extracting URL regex from EML HTML body")
                        eml_links = email_common.extract_event_details(parsed_eml.get("HTML Body", ""), URL_REGEX)

                        parsed_eml.update(eml_links)
                        parsed_eml.update(extract_user_regex)

                    except Exception as e:
                        # If the extract regex fails
                        connector_scope.LOGGER.error("Failed to extract user regex from the eml.")
                        connector_scope.LOGGER.exception(e)

                    connector_scope.LOGGER.info("Creating event from EML")
                    event = eml_connector.create_event(email_id, parsed_eml)

                except Exception as e:
                    # If the event creation fails, event is an empty dict
                    connector_scope.LOGGER.error("Failed to create event. {0}".format(str(e)))
                    connector_scope.LOGGER.exception(e)
                    event = {}

                try:
                    # Create case info
                    case = eml_connector.create_case_info(
                        email_id,
                        event,
                        environment_field_name,
                        environment_regex,
                        connector_scope.context.connector_info.environment
                    )

                    is_overflow = False
                    try:
                        # Check if alert overflow
                        is_overflow = connector_scope.is_overflowed_alert(
                            environment=case.environment,
                            alert_identifier=case.ticket_id,
                            alert_name=case.rule_generator,
                            product=case.device_product
                        )
                    except Exception as e:
                        connector_scope.LOGGER.error("Check if alert is overflow failed. Error: {0}.".format(e))
                        connector_scope.LOGGER.exception(e)

                    if is_overflow:
                        # Skipping this alert (and dot ingest it to siemplify)
                        connector_scope.LOGGER.info(
                            "{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping"
                                .format(alert_name=case.rule_generator,
                                        alert_identifier=case.ticket_id,
                                        environment=case.environment,
                                        product=case.device_product))
                    else:
                        # Ingest the case to siemplify
                        cases_to_ingest.append(case)
                    all_cases.append(case)

                except Exception as e:
                    connector_scope.LOGGER.error("Failed to create CaseInfo")
                    connector_scope.LOGGER.error("Error Message: {}".format(e.message))
                    connector_scope.LOGGER.exception(e)
                    if is_test:
                        raise

        connector_scope.LOGGER.info("Completed processing emails.")

        # Get last successful execution time.
        if original_emails:
            original_emails = sorted(original_emails, key=lambda mail_dict: mail_dict.get(SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY, 1))
            # Last execution time is set to the newest message time
            new_last_run_time = original_emails[-1].get(SIEMPLIFY_MAIL_DICT_UNIXTIME_DATE_KEY, 1)
        else:
            # last_calculated_run_time is datetime object. Convert it to milliseconds timestamp.
            new_last_run_time = convert_datetime_to_unix_time(last_calculated_run_time)

        if not is_test:
            # update last execution time
            connector_scope.save_timestamp(new_timestamp=new_last_run_time)
            connector_scope.LOGGER.info("Created {} cases.".format(len(cases_to_ingest)))

        connector_scope.LOGGER.info("=======Email EML Connector Finish.=======")

        # Return data
        connector_scope.return_package(cases_to_ingest, output_variables, log_items)

    except Exception as e:
        connector_scope.LOGGER.error("Got exception on main handler.")
        connector_scope.LOGGER.exception(e)
        if is_test:
            raise


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print "Main execution started"
        main()
    else:
        print "Test execution started"
        main(is_test=True)
