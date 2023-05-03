from TIPCommon import extract_script_param

from EmailIMAPManager import EmailIMAPManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime


class BaseEmailAction(object):
    """
    Abstract class for Email actions
    """
    # Constants related to Email integration config
    INTEGRATION_NAME = "EmailV2"
    JOIN_DELIMITER = ", "
    MAX_IDS_PRINT = 100
    NOT_CONFIGURED_VALUE = "Not yet configured"

    def __init__(self, script_name):
        """
        Base constructor. It should trigger load of entire integration configuration
        and configuration specific to the current action.
        :param script_name: {str} Name of the current action
        """
        # SiemplifyAction allows us to access many goodies,
        # which Siemplify Platform provides us on an Action level
        self.siemplify = SiemplifyAction()
        self.siemplify.script_name = script_name
        self.logger = self.siemplify.LOGGER

        self.logger.info("================= Main - Param Init =================")

        self.load_integration_configuration()
        self.load_action_configuration()

    def _get_integration_param(self, param_name, default_value=None, input_type=str, is_mandatory=False,
                               print_value=False):
        conf = self.siemplify.get_configuration(BaseEmailAction.INTEGRATION_NAME)
        return extract_script_param(
            siemplify=self.siemplify,
            input_dictionary=conf,
            param_name=param_name,
            default_value=default_value,
            input_type=input_type,
            is_mandatory=is_mandatory,
            print_value=print_value)

    def _get_action_param(self, param_name, default_value=None, input_type=str, is_mandatory=False, print_value=False):
        conf = self.siemplify.parameters
        return extract_script_param(
            siemplify=self.siemplify,
            input_dictionary=conf,
            param_name=param_name,
            default_value=default_value,
            input_type=input_type,
            is_mandatory=is_mandatory,
            print_value=print_value)

    def load_integration_configuration(self):
        """
        Protected method, which should load configuration, specific to entire Email configuration
        """
        # Load Email integration configuration
        self.load_base_integration_configuration()

    # noinspection PyAttributeOutsideInit
    def load_base_integration_configuration(self):
        """
        Loads base integration configuration, which is used by all Email integration actions
        """
        self.from_address = self._get_integration_param(
            param_name="Sender's address",
            is_mandatory=True)
        self.smtp_host = self._get_integration_param(
            param_name="SMTP Server Address",
            default_value='Not yet configured')
        # noinspection PyTypeChecker
        self.smtp_port = self._get_integration_param(
            param_name="SMTP Port",
            default_value='Not yet configured')
        self.username = self._get_integration_param(
            param_name="Username",
            is_mandatory=True)
        self.password = self._get_integration_param(
            param_name="Password",
            is_mandatory=True)
        # noinspection PyTypeChecker
        self.smtp_use_ssl = self._get_integration_param(
            param_name="SMTP USE SSL",
            input_type=bool,
            default_value=True)
        # noinspection PyTypeChecker
        self.smtp_use_auth = self._get_integration_param(
            param_name="SMTP Use Authentication",
            input_type=bool,
            default_value=True)
        self.display_sender_name = self._get_integration_param(
            param_name="Sender's Display Name")

    def validate_configuration(self, host, port, error_message='SMTP or IMAP configuration failed'):
        if host == self.NOT_CONFIGURED_VALUE or port == self.NOT_CONFIGURED_VALUE:
            raise Exception(error_message)

    def load_action_configuration(self):
        """
        Protected method, which should load configuration, specific to the specific Email Action
        """
        raise NotImplementedError()

    def run(self):
        """
        Main Email action method. It wraps some common logic for actions
        """
        self.logger.info("----------------- Main - Started -----------------")

        try:
            status = EXECUTION_STATE_COMPLETED  # Used to flag back to Siemplify system, the action final status
            output_messages = ["Output messages:\n"]  # Human-readable message, showed in UI as the action result
            result_value = False  # Set a simple result value, used for playbook if\else and placeholders.
            failed_entities = []  # If this action contains entity based logic, collect failed entity.identifiers
            successful_entities = []  # If this action contains entity based logic, collect successful entity.identifiers

            status, result_value = self.execute_action(output_messages, successful_entities, failed_entities)

        except Exception as e:
            self.logger.error("General error performing action {}".format(self.SCRIPT_NAME))
            self.logger.exception(e)
            raise  # used to return entire error details - including stacktrace back to client UI. Best for most use cases

        all_messages = "\n  ".join(output_messages)
        self.logger.info("----------------- Main - Finished -----------------")
        self.logger.info(
            "status: {}\n  result_value: {}\n  output_message: {}".format(
                status, result_value, all_messages))
        self.siemplify.end(all_messages, result_value, status)

    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        This abstract method should be implemented to reflect actual behavior to process an entity
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Success flag: {bool} True - success, False - failure.
        """
        status = EXECUTION_STATE_COMPLETED  # Used to flag back to Siemplify system, the action final status

        for entity in self.siemplify.target_entities:
            self.logger.info("Started processing entity: {}".format(entity.identifier))

            if unix_now() >= self.siemplify.execution_deadline_unix_time_ms:
                self.logger.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(self.siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                self.execute_action_per_entity(entity, output_messages)

                successful_entities.append(entity.identifier)
                self.logger.info("Finished processing entity {0}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity.identifier)
                self.logger.error("An error occurred on entity {0}".format(entity.identifier))
                self.logger.exception(e)

        if successful_entities:
            output_messages.append(
                "Successfully processed entities:\n{}".format(
                    "\n  ".join(successful_entities)))
        else:
            output_messages.append("No entities where processed.")

        if failed_entities:
            output_messages.append(
                "Failed processing entities:{}\n".format(
                    "\n  ".join(failed_entities)))
            status = EXECUTION_STATE_FAILED

        return status

    def execute_action_per_entity(self, entity, output_messages):
        """
        Abstract method, which should do something per each entity
        :param entity: {AlertInfo} Actual entity instance along with all related information
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        """
        raise NotImplementedError()

    def search_emails(self,
                      folders,
                      message_ids=None,
                      subject=None,
                      sender=None,
                      recipient=None,
                      only_unread=False,
                      time_filter=None,
                      reply_to=None):
        """
        Common method for emails searching by either message_id, or a number of other optional parameters.
        Logic is: When you know message_id, you only need to check within a bunch of existing folders.
        If message_id is unknown, then it makes sense to search against a number of different criteria.
        :param folders: {list} List of strings representing IMAP folders. Mandatory - should contain ['Inbox'] at least
        :param message_ids: {list} List of specific message_ids of emails to look for. None by default
        :param subject: {str} Subject string, against which all emails would be filtered
        :param sender: {str} Email of the sender, against which all emails be filtered
        :param recipient: {str} Email of the recipient, against which all emails be filtered
        :param only_unread: {bool} Indicate, if search should happen just on unread messages
        :param time_filter: {datetime} Timestamp, after which emails should be searched
        :param reply_to: {str} Specify, that system should filter for mails, which have been a reply to this message_id
        :return: {list} Returns a list of (folder, email_uid) tuple. Where folder represents IMAP folder, where a specific email has been found. Email_uid - email's sequential number
        """
        self.logger.info("Check each of source folders")
        for folder in folders:
            try:
                self.logger.info("Searching in folder={0}".format(folder))

                email_uids_by_folder = []
                if message_ids:
                    self.logger.info("Message IDs {0} were provided. Emails will be filtered by these IDs.".format(
                        self.JOIN_DELIMITER.join(message_ids)))
                    for message_id in message_ids:
                        self.logger.info("Searching emails by message_id={0} within folder={1}".format(
                            message_id, folder))
                        email_uids_by_folder = self.email_imap_manager.receive_mail_ids(
                            folder_name=folder,
                            message_id=message_id
                        )
                        self.logger.info("Found email_uids (printing TOP-{0} from {1}): {2}".format(
                            self.MAX_IDS_PRINT,
                            len(email_uids_by_folder),
                            self.JOIN_DELIMITER.join(email_uids_by_folder[:self.MAX_IDS_PRINT])))
                else:
                    self.logger.info(
                        "No Message IDs were provided. Searching emails by "
                        "subject {0}, sender {1}, recipient {2}, time_filter {3}, "
                        "reply_to {4} and filter only_under {5}".format(
                            subject, sender, recipient, time_filter, reply_to, only_unread
                        ))
                    email_uids_by_folder = self.email_imap_manager.receive_mail_ids(
                        folder_name=folder,
                        subject_filter=subject,
                        time_filter=time_filter,
                        sender=sender,
                        recipient=recipient,
                        reply_to=reply_to,
                        only_unread=only_unread
                    )
                    self.logger.info("Found email_uids (printing TOP-{0} from {1}): {2}".format(
                        self.MAX_IDS_PRINT,
                        len(email_uids_by_folder),
                        self.JOIN_DELIMITER.join(email_uids_by_folder[:self.MAX_IDS_PRINT])))

                for email_id in email_uids_by_folder:
                    yield folder, email_id

            except Exception as e:
                self.logger.error("Failed to search for emails in the folder={0}".format(folder))
                self.logger.exception(e)


class EmailIMAPAction(BaseEmailAction):
    """
    This action provides some additional convenience for actions using IMAP for own functionality
    """

    def __init__(self, script_name):
        """
        Overwriting constructor
        :param script_name: {str} Mandatory name of the Action.
        It's required for Action to work with Siemplify
        """
        # Note: for some reason super(EmailIMAPAction, self).__init__(script_name)
        # doesn't work, so I had to copy-paste all this here.
        self.siemplify = SiemplifyAction()
        self.siemplify.script_name = script_name
        self.logger = self.siemplify.LOGGER

        self.logger.info("================= Main - Param Init =================")

        self.load_integration_configuration()
        self.load_action_configuration()
        error_message = "IMAP configuration is needed to execute action. Please configure IMAP on " \
                        "integration configuration page in Marketplace."
        self.validate_configuration(self.imap_host, self.imap_port, error_message)

        # Instantiate EmailIMAPManager
        self.email_imap_manager = EmailIMAPManager(
            mail_address=self.from_address,
            logger=self.logger,
            environment=None,
        )

        self.email_imap_manager.login_imap(
            host=self.imap_host,
            port=self.imap_port,
            username=self.username,
            password=self.password,
            use_ssl=self.imap_use_ssl)

    # noinspection PyAttributeOutsideInit
    def load_integration_configuration(self):
        """
        Protected method, which should load whole Email integration configuration.
        I'm calling same method of the superclass to avoid copy paste of basic params initiation.
        """
        self.load_base_integration_configuration()

        self.imap_host = self._get_integration_param(
            param_name='IMAP Server Address',
            default_value='Not yet configured')
        # noinspection PyTypeChecker
        self.imap_port = self._get_integration_param(
            param_name='IMAP Port',
            default_value='Not yet configured')
        # noinspection PyTypeChecker
        self.imap_use_ssl = self._get_integration_param(
            param_name='IMAP USE SSL',
            input_type=bool,
            default_value=True)

    def load_action_configuration(self):
        raise NotImplementedError()

    def execute_action_per_entity(self, entity, output_messages):
        raise NotImplementedError()