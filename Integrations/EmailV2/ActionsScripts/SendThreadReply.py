from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from EmailSMTPManager import EmailSMTPManager
from EmailActions import EmailIMAPAction
from EmailCommon import load_attachments_to_dict


class SendThreadReplyAction(EmailIMAPAction):
    """
    This class should be used for execution of flow related to SendThreadReply action
    SendThreadReply should get original email by message id and send thread reply to it
    SMTP server
    """
    SCRIPT_NAME = "EmailV2 - Send Thread Reply"

    def __init__(self):
        """
        SendThreadReplyAction constructor. Loads integration configuration and initializes EmailManager instance
        """
        super(SendThreadReplyAction, self).__init__(SendThreadReplyAction.SCRIPT_NAME)
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

    def load_action_configuration(self):
        """
        Method should load configuration, specific to the SendThreadReply Action
        """
        self.message_id = self._get_action_param(param_name="Message ID", is_mandatory=True, print_value=True)
        folders_string = self._get_action_param(param_name="Folder Name", is_mandatory=True, default_value="Inbox")
        self.folders = [f.strip() for f in folders_string.split(",") if f.strip()] if folders_string else []
        self.body = self._get_action_param(param_name="Content", is_mandatory=True)
        attachment_paths_list = self._get_action_param(param_name="Attachment Paths", is_mandatory=False,
                                                       print_value=True)
        self.reply_all = self._get_action_param(param_name="Reply All", input_type=bool, print_value=True)
        reply_to_string = self._get_action_param(param_name="Reply To", print_value=True)
        self.reply_to = [item.strip() for item in reply_to_string.split(",") if item.strip()] if reply_to_string else []

        if attachment_paths_list:
            self.attachment_paths = [a.strip() for a in attachment_paths_list.split(",") if a.strip()]
        else:
            self.attachment_paths = []

    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Get original email by message id and send thread reply to it
        :param output_messages: {list} Mutable list of output messages
        :param successful_entities: {list} N/A in case of SendThreadReply
        :param failed_entities: {list} N/A in case of SendThreadReply
        :return: {tuple} status, result_value
        """
        # Create a dict with all required attachments to the email
        attachments_dict = load_attachments_to_dict(siemplify_logger=self.logger, attachment_paths=self.attachment_paths)
        original_message = None
        result_value = True
        status = EXECUTION_STATE_COMPLETED

        # Reply to first found email
        try:
            for folder, email_uid in self.search_emails(folders=self.folders, message_ids=[self.message_id]):
                self.logger.info(f"Fetching email data with email_uid={email_uid} in folder={folder}")
                original_message = self.email_imap_manager.get_message_data_by_message_id(
                    email_uid=email_uid,
                    folder_name=folder
                )

                if not original_message:
                    self.logger.info(f"No emails were found for email_uid={email_uid} in folder={folder}")
                    continue

                break

            if original_message:
                if self.reply_all:
                    addresses = list(set(original_message.recipients + original_message.senders + original_message.cc))

                    if self.from_address in addresses:
                        addresses.remove(self.from_address)

                    if not addresses:
                        raise Exception("if you want to send a reply only to your own email address, you need to work "
                                        "with \"Reply To\" parameter.")
                elif self.reply_to:
                    addresses = self.reply_to
                else:
                    addresses = original_message.senders

                msg_id = self.email_smtp_manager.send_mail_html_embedded_photos(
                    html_body=self.body,
                    subject=original_message.subject,
                    to_addresses=",".join(addresses),
                    original_message=original_message,
                    attachments=attachments_dict
                )

                json_result = {
                    "message_id": msg_id,
                    "recipients": ",".join(addresses)
                }
                self.siemplify.result.add_result_json(json_result)

                output_messages.append(f"Successfully sent reply to the message with ID {self.message_id}.")

            else:
                result_value = False
                output_messages.append(f"Message with ID {self.message_id} was not found")

        except Exception as e:
            self.logger.error(f"General error performing action {SendThreadReplyAction.SCRIPT_NAME}")
            self.logger.exception(e)
            result_value = False
            status = EXECUTION_STATE_FAILED
            output_messages.append(f"Error executing action \"Send Thread Reply\". Reason: {e}")

        return status, result_value


@output_handler
def main():
    action = SendThreadReplyAction()
    action.run()


if __name__ == "__main__":
    main()

