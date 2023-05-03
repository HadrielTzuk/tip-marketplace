from EmailSMTPManager import EmailSMTPManager
from EmailActions import BaseEmailAction
from SiemplifyUtils import output_handler, utc_now
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT


class SendEmailAction(BaseEmailAction):
    """
    This class should be used for execution of flow related to SendEmail action.
    SendEmail should simply send an email through selected SMTP server.
    This action doesn't support any retry logic.
    """

    SCRIPT_NAME = "EmailV2 - Send Email"

    def __init__(self):
        """
        SendEmailAction constructor. Loads integration configuration and initializes EmailManager instance
        """

        super(SendEmailAction, self).__init__(SendEmailAction.SCRIPT_NAME)
        error_message = "SMTP configuration is needed to execute action. Please configure SMTP on " \
                        "integration configuration page in Marketplace."
        self.validate_configuration(self.smtp_host, self.smtp_port, error_message)

        # Instantiate EmailSMTPManager
        self.email_smtp_manager = EmailSMTPManager(self.from_address)

        # And Login to it
        self.email_smtp_manager.login_smtp(
            host=self.smtp_host,
            port=self.smtp_port,
            username=self.username,
            password=self.password,
            use_ssl=self.smtp_use_ssl,
            use_auth=self.smtp_use_auth)

    # noinspection PyAttributeOutsideInit
    def load_action_configuration(self):
        """
        Protected method, which should load configuration, specific to the SendEmail Action
        """
        self.send_to = self._get_action_param(param_name="Recipients",
                                              is_mandatory=True)
        self.cc = self._get_action_param(param_name="CC")
        self.bcc = self._get_action_param(param_name="BCC")
        self.subject = self._get_action_param(param_name="Subject",
                                              is_mandatory=True)
        self.body = self._get_action_param(param_name="Content",
                                           is_mandatory=True)
        self.return_msg_id = self._get_action_param(param_name="Return message id for the sent email",
                                                    input_type=bool,
                                                    default_value=False)
        attachment_paths_list = self._get_action_param(param_name="Attachments Paths")
        if attachment_paths_list:
            self.attachment_paths = [a.strip() for a in attachment_paths_list.split(",") if a.strip()]
        else:
            self.attachment_paths = []

    # noinspection PyUnusedLocal
    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Sends email with all required attachments
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} N/A in case of SendEmail. List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} N/A in case of SendEmail. List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Success flag: {bool} True - success, False - failure.
        """
        # Create a dict with all required attachments to the email
        attachments_dict = self.load_attachments_to_dict()

        try:
            # Send an email and save it's message_id
            self.logger.info("Sending email")
            msg_id = self.email_smtp_manager.send_mail_html_embedded_photos(
                to_addresses=self.send_to,
                subject=self.subject,
                html_body=self.body,
                cc=self.cc,
                bcc=self.bcc,
                display_sender_name=self.display_sender_name,
                attachments=attachments_dict,
            )
        except Exception as e:
            message = "Failed to send email!"
            self.logger.error(message)
            self.logger.exception(e)
            output_messages.append(message)
            return EXECUTION_STATE_FAILED, False

        message = "Email has been send successfully"
        # Save result JSON, if required
        if self.return_msg_id:
            self.logger.info("Saving result JSON")
            json_result = {
                "message_id": msg_id,
                "date": utc_now(),
                "recipients": self.send_to
            }
            self.siemplify.result.add_result_json(json_result)
            message = "Mail sent successfully. Mail message id is: {0}".format(msg_id)

        output_messages.append(message)
        self.logger.info(message)
        return EXECUTION_STATE_COMPLETED, True

    def load_attachments_to_dict(self):
        attachments_dict = {}
        self.logger.info("Reading attachments from disk")
        for attachment_path in self.attachment_paths:
            try:
                with open(attachment_path, "rb") as f:
                    attachments_dict[attachment_path] = f.read()
            except Exception as e:
                self.logger.error("Unable to read attachment {} from disk".format(attachment_path))
                self.logger.exception(e)
        return attachments_dict


@output_handler
def main():
    action = SendEmailAction()
    action.run()


if __name__ == "__main__":
    main()
