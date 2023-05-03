# -*- coding: utf-8 -*-
import sys
import re
import base64
import os
from SiemplifyDataModel import Attachment
from SiemplifyConnectors import CaseInfo, SiemplifyConnectorExecution
from SiemplifyUtils import output_handler
from EmailIMAPManager import EmailIMAPManager
from EmailCommon import DEFAULT_REGEX_MAP, URLS_REGEX, safe_str_cast, build_regex_map, is_invalid_prefix, \
    InvalidParameterError, transform_dict_keys
from EnvironmentCommon import GetEnvironmentCommonFactory
from TIPCommon import extract_script_param, get_last_success_time, save_timestamp, is_overflowed, read_ids, write_ids
import uuid


def create_siemplify_case_wall_attachment_object(full_file_name, file_contents):
    # type: (bytes, str) -> Attachment
    """
    Create attachment object with the original email
    :param full_file_name: {string} File name of the attachment
    :param file_contents: {string} Attachment content as a string
    :return: {Attachment} of attachment object
    """

    base64_blob = base64.b64encode(file_contents).decode()

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


class NewCaseBuilder(object):
    """
    Builds New CaseInfo based on available data
    """
    ATTACHMENT_DESCRIPTION = 'This is the original message as EML'
    EMAIL_EML_RESOLUTION = '.eml'
    EMAIL_MSG_RESOLUTION = '.msg'
    EMAIL_ICS_RESOLUTION = '.ics'
    DEFAULT_NAME = "Monitored Mailbox <{0}>"
    DEFAULT_PRIORITY = 40  # Defaulting to Low.
    DEFAULT_TIMESTAMP = 1
    DEFAULT_VENDOR_NAME = "Mail"
    DEFAULT_PRODUCT_NAME = "Mail"
    DEFAULT_SUBJECT_TEXT = "Message Has No Subject"
    DEFAULT_MAIL_ADDRESS = "Undefined"
    DEFAULT_EMAIL_NAME = "{0}_{1}"
    DEFAULT_EML_FILE_NAME = "{0}.eml"
    EVENTS_SYSTEM_KEYS = ['device_product', 'event_name', 'original_message_id', 'event_type', 'vendor',
                          'event_name_mail_type', 'monitored_mailbox_name']

    def __init__(self,
                 email,
                 siemplify,
                 logger,
                 env_default,
                 mail_address=None,
                 env_field_name=None,
                 env_field_regex=None,
                 product_field=None,
                 ):
        """
        Basic constructor
        :param email: {EmailDataModels.EmailModel} EmailModel instance with fulfilled email parameters
        :param logger: {Siemplify.LOGGER} Logger instance
        :param env_default: {str} Default environment name
        :param mail_address: {str} Email address of the current monitored mailbox
        :param env_field_name: {str} Email field name, which may contain information on environment, which will be extracted by the regex present in env_field_regex field.
        :param env_field_regex: {str} Regex to extract actual environment name from the env_field_name
        :param product_field: {str} Product_field to use (if given)
        """
        self.email = email
        self.siemplify = siemplify
        self.logger = logger
        self.mail_address = mail_address
        if not self.mail_address:
            self.mail_address = self.DEFAULT_MAIL_ADDRESS
        self.env_default = env_default
        self.env_field_name = env_field_name
        self.env_field_regex = env_field_regex
        self.product_field = product_field

        self.environment_handle = GetEnvironmentCommonFactory.create_environment_manager(
            siemplify,
            self.env_field_name,
            self.env_field_regex
        )

        self.case = CaseInfo()
        self.case.attachments = []

    def create_case(self, prefix=None, is_original_mail=False, additional_events=None):
        """
        Fills in case common information
        :param prefix: {str} Prefix for events
        :param is_original_mail: {bool} Specifies if provided mail is the original one or no
        :param additional_events: {list} List of additional event for the case
        """
        self.logger.info("NewCaseBuilder.create_case() - Start")
        # Create the CaseInfo
        if not self.email.message_id:
            raise AttributeError("Email().message_id is None or empty.")
        default_mailbox = self.DEFAULT_NAME.format(self.mail_address)
        timestamp = self.email.unixtime_date
        email_name = self.DEFAULT_EMAIL_NAME.format(self.mail_address, self.email.unixtime_date)

        self.case.identifier = self.email.message_id
        self.case.ticket_id = self.email.message_id
        self.case.display_id = self.email.message_id if is_original_mail else str(uuid.uuid4())
        self.case.name = email_name
        self.case.rule_generator = default_mailbox
        self.case.start_time = timestamp
        self.case.end_time = timestamp
        self.case.priority = self.DEFAULT_PRIORITY
        self.case.device_vendor = self.DEFAULT_VENDOR_NAME
        self.case.device_product = self.product_field if self.product_field else self.DEFAULT_PRODUCT_NAME
        self.email.event_name = self.case.name
        self.case.events = [transform_dict_keys(
            original_dict=self.email.to_dict(as_event=True, is_original_mail=is_original_mail),
            prefix=prefix,
            keys_to_except=self.EVENTS_SYSTEM_KEYS)
        ]

        if additional_events:
            self.case.events.extend(additional_events)

        self.logger.info("NewCaseBuilder.create_case() - Finish")

    def update_environment(self):
        """
        Update environment information for the case
        """
        self.logger.info("NewCaseBuilder.update_environment() - Start")
        self.case.environment = self.environment_handle.get_environment(self.case.events[0])
        self.logger.info("NewCaseBuilder.update_environment() - Finish")

    def attach_original_email(self):
        """
        Attaches original email to the case
        """
        self.logger.info("NewCaseBuilder.attach_original_email() - Start")

        if not self.email.original_message:
            self.logger.info("EmailModel().original_message is None or empty - unable to attach it.")
            return
        if not self.email.subject:
            self.logger.info("EmailModel().subject is None or empty - unable to attach original_message.")
            return

        try:
            attachment_object = create_siemplify_case_wall_attachment_object(
                self.DEFAULT_EML_FILE_NAME.format(self.email.subject),
                self.email.original_message.encode())

            # Add to case_info
            self.case.attachments.append(attachment_object)

            self.logger.info("Successfully attached original message as EML.")
            self.logger.info("NewCaseBuilder.attach_original_email() - Finish")
        except Exception as e:
            self.logger.error("Failed to attach original EML for email={0}".format(self.email.email_uid))
            self.logger.exception(e)

    def attach_emails(self, prefix=None):
        """
        Adds all attached emails to events
        """
        for index, email in enumerate(self.email.attached_emails):
            try:
                email.original_message_id = self.case.identifier
                email.event_name = self.case.name
                self.case.events.append(transform_dict_keys(
                    original_dict=email.to_dict(as_event=True, is_original_mail=False),
                    prefix=prefix,
                    suffix=index+1,
                    keys_to_except=self.EVENTS_SYSTEM_KEYS))
                self.logger.info(
                    "Attached {0} to the case as another event.".format(email.message_id))
            except Exception as e:
                self.logger.error("Unable to attach email {0} as another event".format(email.message_id))
                self.logger.exception(e)

    def attach_files(self):
        """
        Attaches all email attachments with exception of emails to the case
        """
        for attachment in self.email.attachments:
            try:
                if self.EMAIL_EML_RESOLUTION not in attachment.file_name.lower() and \
                        self.EMAIL_MSG_RESOLUTION not in attachment.file_name.lower() and \
                        self.EMAIL_ICS_RESOLUTION not in attachment.file_name.lower():
                    self.logger.info("Trying to attach file to case: {}".format(attachment.file_name))
                    packed_attachment = create_siemplify_case_wall_attachment_object(
                        attachment.file_name,
                        attachment.file_contents
                    )
                    self.case.attachments.append(packed_attachment)
                    self.logger.info(
                        "Attached {} to the case as a file.".format(attachment.file_name))
            except Exception as e:
                self.logger.error("Unable to attach {0} to the case".format(attachment.file_name))
                self.logger.exception(e)

    def get_case(self):
        """
        Returns filled in case instance
        :return: {CaseInfo} Filled in case instance
        """
        return self.case


class BaseEmailConnector(object):
    """
    Base class for EmailConnector containing most common functionality
    """

    DEFAULT_OFFSET_IN_DAYS = 5
    DEFAULT_MAX_EMAILS_PER_CYCLE = 10

    def __init__(self, config=None, is_test=False, connector_name=None):
        """
        Common constructor for BaseEmailConnector
        """
        self.connector_scope = SiemplifyConnectorExecution()
        self.connector_scope.script_name = connector_name
        self.logger = self.connector_scope.LOGGER
        self.environment_name = self.connector_scope.context.connector_info.environment

        self.is_test = is_test
        if self.is_test:
            self.logger.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

        self._load_connector_configuration(config)
        self._load_connector_whitelist_rules()
        self._initialize_managers()

    def _get_connector_param(self, param_name, config, default_value=None, input_type=str, is_mandatory=False, print_value=False):
        return extract_script_param(
            siemplify=self.connector_scope,
            input_dictionary=config,
            param_name=param_name,
            default_value=default_value,
            input_type=input_type,
            is_mandatory=is_mandatory,
            print_value=print_value)

    def _load_connector_configuration(self, config):
        """
        Loads all connector configurations from Siemplify
        """
        self.logger.info("==================== Main - Param Init ====================")

        conf = self.connector_scope.parameters if not config else config
        self.imap_host = self._get_connector_param(param_name="IMAP Server Address",
                                                   config=conf,
                                                   is_mandatory=True)
        self.imap_port = self._get_connector_param(param_name="IMAP Port",
                                                   config=conf,
                                                   input_type=int,
                                                   is_mandatory=True)
        self.imap_use_ssl = self._get_connector_param(param_name="IMAP USE SSL",
                                                      config=conf,
                                                      input_type=bool,
                                                      is_mandatory=True)
        self.username = self._get_connector_param(param_name="Username",
                                                  config=conf,
                                                  is_mandatory=True)
        self.password = self._get_connector_param(param_name="Password",
                                                  config=conf,
                                                  is_mandatory=True)

        folders_string = self._get_connector_param(param_name="Folder to check for emails",
                                                   config=conf,
                                                   is_mandatory=True)
        self.folders = [f.strip() for f in folders_string.split(",")] if folders_string else []

        self.offset_in_days = self._get_connector_param(param_name="Offset Time In Days",
                                                        config=conf,
                                                        input_type=int,
                                                        default_value=self.DEFAULT_OFFSET_IN_DAYS)
        self.max_emails_per_cycle = self._get_connector_param(param_name="Max Emails Per Cycle",
                                                              config=conf,
                                                              input_type=int,
                                                              default_value=self.DEFAULT_MAX_EMAILS_PER_CYCLE)
        self.attach_original_eml = self._get_connector_param(param_name="Attach Original EML",
                                                             config=conf,
                                                             input_type=bool,
                                                             default_value=False)
        self.unread_only = self._get_connector_param(param_name="Unread Emails Only",
                                                     config=conf,
                                                     input_type=bool,
                                                     default_value=False)
        self.mark_as_read = self._get_connector_param(param_name="Mark Emails as Read",
                                                      config=conf,
                                                      input_type=bool,
                                                      default_value=False)
        self.server_time_zone = self._get_connector_param(param_name="Server Time Zone",
                                                          config=conf,
                                                          default_value='UTC')
        self.environment_field_name = self._get_connector_param(param_name="Environment Field Name",
                                                                config=conf)
        self.environment_regex = self._get_connector_param(param_name="Environment Regex Pattern",
                                                           config=conf)
        self.proxy_server = self._get_connector_param(param_name="Proxy Server Address",
                                                      config=conf)
        self.proxy_username = self._get_connector_param(param_name="Proxy Username",
                                                        config=conf)
        self.proxy_password = self._get_connector_param(param_name="Proxy Password",
                                                        config=conf)
        self.product_field = self._get_connector_param(param_name="DeviceProductField",
                                                        config=conf)
        self.headers_to_add_to_events = self._get_connector_param(
            param_name='Additional headers to extract from emails',
            config=conf)
        self.headers_to_add_to_events = [header.strip()
                                         for header in self.headers_to_add_to_events.split(',')
                                         if header and header.strip()] if self.headers_to_add_to_events else []
        self.subject_exclude_regex = self._get_connector_param(param_name="Exclusion Subject Regex", config=conf)
        self.body_exclude_regex = self._get_connector_param(param_name="Exclusion Body Regex", config=conf)

        self.original_mail_prefix = self._get_connector_param(param_name="Original Received Mail Prefix", config=conf,
                                                              print_value=True)
        self.attached_mail_prefix = self._get_connector_param(param_name="Attached Mail File Prefix", config=conf,
                                                              print_value=True)
        self.alert_per_attachment = self._get_connector_param(param_name="Create a Separate Siemplify Alert per "
                                                                         "Attached Mail File?",
                                                              config=conf, input_type=bool, print_value=True)

    def _load_connector_whitelist_rules(self):
        """
        Loads regex map from whitelist rules in order to extract information from emails and include it to event.
        """
        whitelist_rules = self.connector_scope.whitelist if self.connector_scope.whitelist else []
        self.logger.info("Current whitelist rules are: {}".format(whitelist_rules))

        self.regex_map = DEFAULT_REGEX_MAP
        if whitelist_rules:
            self.regex_map = build_regex_map(whitelist_rules)

        self.logger.info("The current regex map is: {}".format(self.regex_map))

    def _initialize_managers(self):
        """
        Abstract method to initialize all required managers
        """
        raise NotImplementedError()

    def is_matching_exclude_patterns(self, message, subject_exclude_pattern=None, body_exclude_pattern=None):
        """
        Determine if message body matching provided regexp
        :param message: {EmailDataModels.EmailModel} Message object
        :param subject_exclude_pattern: {str} Regex pattern, which would exclude emails with matching subject.
        :param body_exclude_pattern: {str} Regex pattern, which would exclude emails with matching body.
        :return: {bool} True if matches one of the exclude patterns; False - otherwise.
        """
        body_parts = [message.html_body, message.text_body, message.body]

        if body_exclude_pattern:
            for part in body_parts:
                if part and re.findall(body_exclude_pattern, part):
                    return True

        if subject_exclude_pattern:
            if message.subject and re.findall(subject_exclude_pattern, message.subject):
                return True

        return False

    def run(self):
        """
        Main method of Connector execution. It uses template pattern.
        """
        self.logger.info("------------------- Main - Started -------------------")

        try:
            if self.original_mail_prefix and is_invalid_prefix(self.original_mail_prefix):
                raise InvalidParameterError("Original Received Mail Prefix configured contains a space, which is not "
                                            "supported, please remove any spaces and try again.")

            if self.attached_mail_prefix and is_invalid_prefix(self.attached_mail_prefix):
                raise InvalidParameterError("Attached Mail File Prefix configured contains a space, which is not "
                                            "supported, please remove any spaces and try again.")

            last_calculated_run_time = get_last_success_time(siemplify=self.connector_scope,
                                                             offset_with_metric={'days': self.offset_in_days})

            self.logger.info("Calculated last run time. Last run time is: {}".format(last_calculated_run_time))
            self.logger.info("Last execution time: {}".format(last_calculated_run_time))

            # Read already existing email ids
            existing_ids = read_ids(self.connector_scope)
            self.connector_scope.LOGGER.info(f"Successfully loaded {len(existing_ids)} existing ids")

            alerts = []
            for index, alert_id in enumerate(self._search_alerts(last_calculated_run_time), 1):
                try:
                    if self.is_test and index > 1:
                        self.logger.info("As this is a test run, limiting number of alerts processed to 1.")
                        break

                    if len(alerts) >= self.max_emails_per_cycle:
                        # Provide slicing for the alerts amount.
                        self.connector_scope.LOGGER.info(
                            "Reached max number of emails cycle. No more emails will be processed in this cycle."
                        )
                        break

                    email_alerts = self._fetch_alert(alert_id, existing_ids)

                    if email_alerts:
                        alerts.extend([email_alert for email_alert in email_alerts if email_alert])

                        if self.alert_per_attachment and len(email_alerts) > 1:
                            self.logger.info("Added Alert {} and Alerts per attached mail files to package results"
                                             .format(alert_id))
                        else:
                            self.logger.info("Added Alert {} to package results".format(alert_id))

                except Exception as e:
                    self.logger.error("Failed to process alert {}".format(alert_id))
                    self.logger.exception(e)

            if not self.is_test:
                self.connector_scope.LOGGER.info("Saving existing ids.")
                write_ids(self.connector_scope, existing_ids)
                save_timestamp(self.connector_scope, alerts, 'end_time')

        except Exception as e:
            self.logger.error(f"Got exception on main handler. Error: {e}")
            self.logger.exception(e)

            if self.is_test:
                raise

        self.logger.info("------------------- Main - Finished -------------------")
        self.connector_scope.return_package(alerts)

    def _search_alerts(self, last_run_time):
        raise NotImplementedError()

    def _fetch_alert(self, alert_id, existing_ids):
        raise NotImplementedError()


class EmailConnector(BaseEmailConnector):
    """
    Class wrapping logic of EmailConnector.
    """
    CONNECTOR_NAME = "EmailConnector"
    PRODUCT_NAME = VENDOR_NAME = "Mail"

    def __init__(self, config=None, is_test=False):
        # type: (dict, bool) -> None
        """
        Default constructor for the EmailConnector
        :param is_test: Runs email collection in a limited manner in test purposes
        """
        super(EmailConnector, self).__init__(
            config=config,
            is_test=is_test,
            connector_name=self.CONNECTOR_NAME)

    def _initialize_managers(self):
        # type: () -> None
        """
        Initializes EmailIMAPManager and EmailSMTPManager
        """

        self.logger.info("Connecting to Email manager")
        self.email_imap_manager = EmailIMAPManager(
            mail_address=self.username,
            logger=self.logger,
            environment=self.environment_name,
            regex_map=self.regex_map,
            proxy_server=self.proxy_server,
            proxy_username=self.proxy_username,
            proxy_password=self.proxy_password
        )

        self.logger.info("Login to IMAP")
        self.email_imap_manager.login_imap(
            host=self.imap_host,
            port=self.imap_port,
            username=self.username,
            password=self.password,
            use_ssl=self.imap_use_ssl)

    def _search_alerts(self, last_run_time):
        """
        Override of an abstract method, which searches for emails to retrieve
        :param last_run_time: {arrow.datetime} Emails should be retrieved after this timestamp
        :return: {tuple} returning a tuple of (folder, email_id) values.
        """
        for folder in self.folders:
            try:
                filtered_mails_ids = self.email_imap_manager.receive_mail_ids(
                    folder_name=folder,
                    time_filter=last_run_time,
                    only_unread=self.unread_only)

                for email_uid in filtered_mails_ids:
                    # I may search through multiple mailboxes, thus in order to retrieve email later on,
                    # I need to know not only it's sequential number, but also it's folder
                    yield folder, email_uid

            except Exception as e:
                self.logger.error("Failed to search for emails in the folder={0}".format(folder))
                self.logger.exception(e)

        self.logger.info("Found {} emails.".format(len(filtered_mails_ids)))

    def is_matching_filter_patterns(self, email):
        """
        Is email subject and body matching to exclude patterns
        :param email: {EmailDataModels.EmailModel}
        :return {bool}:
        """
        if self.subject_exclude_regex or self.body_exclude_regex:
            if self.is_matching_exclude_patterns(email, self.subject_exclude_regex, self.body_exclude_regex):
                # Excluded email with pattern should stay unread
                self._mark_email_as_read(email_id=email.email_uid, mark_as_read=False)
                self.logger.info("Email with message_id={} was ignored after filtering by regexes"
                                 .format(email.message_id))
                return False

        return True

    def _fetch_alert(self, alert_id, existing_ids):
        """
        Override of an abstract method, which fetches full details of email by it's ID.
        Afterwards does all required processing to build a case
        :param alert_id: {tuple} (folder_name, email_uid)
        :param existing_ids: {list} List of already existing ids
        :return: {CaseInfo} An instance of resulting CaseInfo()
        """
        self.logger.info("-------------- Started processing Alert {}".format(alert_id), alert_id=alert_id)

        # Unpacking alert_id into folder and according email_uid
        folder, email_uid = alert_id
        self.logger.info("Fetching email with email_uid={0} in folder={1}".format(
            email_uid, folder), alert_id=alert_id)

        # Retrieve email object along with all it's attachments
        email = self.email_imap_manager.get_message_data_by_message_id(
            email_uid=email_uid,
            folder_name=folder,
            include_raw_eml=self.attach_original_eml,
            mark_as_read=self.mark_as_read,
            additional_headers=self.headers_to_add_to_events
        )

        if email.message_id in existing_ids:
            self.logger.info(f"The email with email_uid={email_uid} in folder={folder} skipped since it has been "
                             f"fetched before", alert_id=alert_id)
            return None

        if not email:
            self.logger.error("No emails were found for email_uid={0} in folder={1}".format(
                email_uid, folder), alert_id=alert_id)
            return None
        self.logger.info("Fetched email successfully with email_uid={0} and message_id={1}".format(
            email_uid, email.message_id), alert_id=alert_id)

        existing_ids.append(email.message_id)

        if not self.is_matching_filter_patterns(email):
            self._mark_email_as_read(email.email_uid, self.mark_as_read)
            return None

        # Create case info
        cases = self._create_cases_info(email)
        self.logger.info(
            "Created case on the base of email.message_id={}".format(email.message_id), alert_id=alert_id)

        for index, case in enumerate(cases):
            if is_overflowed(self.connector_scope, case, self.is_test):
                self.logger.info(
                    '{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. Skipping.'
                        .format(alert_name=str(case.rule_generator),
                                alert_identifier=str(case.ticket_id),
                                environment=str(case.environment),
                                product=str(case.device_product)))
                self.logger.info("Current case is overflow.", alert_id=alert_id)
                self.logger.error("Alert with alert_id={} found as overflow alert. Skipping.".format(alert_id))
                cases.pop(index)

        self._mark_email_as_read(email.email_uid, self.mark_as_read)

        self.logger.info("-------------- Finished processing Alert {}".format(alert_id), alert_id=alert_id)

        return cases

    def _create_case_info(self, email, is_original_mail=False, additional_events=None):
        """
        Create Case instance based on extracted Event
        :param email: {dict} EmailDataModels.EmailModel() instance
        :param is_original_mail: {bool} Specifies if provided mail is the original one or no
        :param additional_events: {list} List of additional events for the case
        :return: {CaseInfo} case
        """
        self.logger.info("Start case creation")
        # Validate email message id exists
        email_id = email.message_id
        if not email_id:
            raise AttributeError("Found mail, cannot get its message id")

        builder = NewCaseBuilder(
            email,
            self.connector_scope,
            self.logger,
            self.environment_name,
            self.email_imap_manager.mail_address,
            self.environment_field_name,
            self.environment_regex,
            self.product_field
        )
        prefix = self.original_mail_prefix if is_original_mail else self.attached_mail_prefix
        additional_events = additional_events if additional_events else []
        builder.create_case(prefix, is_original_mail, additional_events)
        builder.update_environment()

        if is_original_mail:
            if self.attach_original_eml:
                builder.attach_original_email()

            if not self.alert_per_attachment:
                builder.attach_emails(self.attached_mail_prefix)

            builder.attach_files()

        res = builder.get_case()

        self.logger.info("Created case: {}".format(res))

        return res

    def _create_cases_info(self, email):
        """
        Create Cases instances based on extracted email and its email attachments
        :param email: {dict} EmailDataModels.EmailModel() instance
        :return: {list} List of CaseInfo
        """
        cases = [self._create_case_info(email, is_original_mail=True)]

        if self.alert_per_attachment and email.attached_emails:
            for attached_email in email.attached_emails:
                cases.append(self._create_case_info(attached_email, additional_events=[cases[0].events[0]]))

        return cases


    def _mark_email_as_read(self, email_id, mark_as_read):
        # type: (str, bool) -> None
        """
        Allows to mark read email via IMAP
        :param email_id: {str} Email unique identifier
        :param mark_as_read: {bool} If True, email should be marked as read on the server
        """
        try:
            # Mark specific email as read/unread because fetching emails automatically mark them as read.
            # Mark the mail as read only if succeeded creating case.
            self.email_imap_manager.mark_email_as_read(email_id, mark_as_read)
        except Exception as e:
            self.logger.error(
                "Failed to mark email as read. Error message: {}".format(str(e)))
            self.logger.exception(e)
            if self.is_test:
                raise


@output_handler
def main(is_test=False):
    email_connector = EmailConnector(is_test=is_test)
    email_connector.run()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print("Main execution started")
        main()
    else:
        print("Test execution started")
        main(is_test=True)
