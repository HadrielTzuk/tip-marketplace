from EmailActions import EmailIMAPAction
from EmailCommon import load_attachments_to_dict
from EmailDataModels import EmailModel
from EmailSMTPManager import EmailSMTPManager, HUMAN_READABLE_EMAIL_DATE_FORMAT, ESCAPED_HTML_BRACKETS_WRAP

from ScriptResult import EXECUTION_STATE_COMPLETED
from SiemplifyUtils import output_handler, utc_now


class ForwardEmailAction(EmailIMAPAction):
    """
    This class should be used for execution of flow related to ForwardEmail action.
    ForwardEmail should fetch the forwarded email, attach it's body and attachments to a newly created email and send it through selected
    SMTP server.
    This action doesn't support any retry logic.
    """

    SCRIPT_NAME = "EmailV2 - Forward Email"
    FORWARDED_EMAIL_HTML_TEMPLATE = """        
        <br>
        <br>
        ---------- Forwarded message ----------<br>
        From: {sender}<br>
        Date: {email_date}<br>
        Subject: {subject}<br>
        To: {recipients}<br>
        <br>
        <br>
        {html_content}
    """

    def __init__(self):
        """
        ForwardEmailAction constructor. Loads integration configuration and initializes EmailManager instance
        """

        super(ForwardEmailAction, self).__init__(ForwardEmailAction.SCRIPT_NAME)
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
        self.send_to = self._get_action_param(param_name="Recipients", is_mandatory=True, print_value=True)
        self.cc = self._get_action_param(param_name="CC", is_mandatory=False, print_value=True)
        self.bcc = self._get_action_param(param_name="BCC", is_mandatory=False, print_value=True)
        self.subject = self._get_action_param(param_name="Subject", is_mandatory=True, print_value=True)
        self.body = self._get_action_param(param_name="Content", is_mandatory=False, default_value='')
        folders_string = self._get_action_param(param_name="Folder Name", default_value="Inbox")
        self.folders = [f.strip() for f in folders_string.split(",") if f.strip()] if folders_string else []
        self.return_msg_id = self._get_action_param(param_name="Return message id for the forwarded email", input_type=bool,
                                                    default_value=False, print_value=True)
        self.forward_message_id = self._get_action_param(param_name="Message ID of email to forward", is_mandatory=True, print_value=True)
        attachment_paths_list = self._get_action_param(param_name="Attachments Paths", is_mandatory=False, print_value=True)
        if attachment_paths_list:
            self.attachment_paths = [a.strip() for a in attachment_paths_list.split(",") if a.strip()]
        else:
            self.attachment_paths = []

    def build_forward_email_message(self, new_body: str, email_to_forward: EmailModel) -> str:
        """
        Builds html template of forwarded email content
        :return: {str} HTML template of the forwarded message
        """
        forwarded_email_html_content = self.FORWARDED_EMAIL_HTML_TEMPLATE.format(
            sender=ESCAPED_HTML_BRACKETS_WRAP.format(email_to_forward.original_sender),
            email_date=email_to_forward.email_date_aware.strftime(HUMAN_READABLE_EMAIL_DATE_FORMAT),
            subject=email_to_forward.subject,
            recipients=', '.join(ESCAPED_HTML_BRACKETS_WRAP.format(recipient) for recipient in email_to_forward.recipients),
            html_content=email_to_forward.html_body
        )
        return f"""{new_body}{forwarded_email_html_content}"""

    # noinspection PyUnusedLocal
    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Forward email with all required attachments
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} N/A in case of ForwardEmail. List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} N/A in case of ForwardEmail. List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Success flag: {bool} True - success, False - failure.
        """
        # Create a dict with all required attachments to the email
        attachments_dict = load_attachments_to_dict(siemplify_logger=self.logger, attachment_paths=self.attachment_paths)
        email_to_forward_found = False

        # Forward first found email
        for folder, email_uid in self.search_emails(folders=self.folders, message_ids=[self.forward_message_id]):
            try:
                self.logger.info("Fetching email message data with email_uid={0} in folder={1}".format(
                    email_uid, folder))
                email_to_forward = self.email_imap_manager.get_message_data_by_message_id(
                    email_uid=email_uid,
                    folder_name=folder,
                    include_raw_eml=True
                )
                if not email_to_forward:
                    self.logger.info("No emails were found for email_uid={0} in folder={1}".format(
                        email_uid, folder))
                    continue
                email_to_forward_found = True
                self.logger.info("Fetched email with email_uid={0} and message_id={1}".format(email_uid, email_to_forward.message_id))
                try:
                    # Include original attachments in the forwarded email
                    if email_to_forward.attachments:
                        self.logger.info(f"Found {len(email_to_forward.attachments)} attachments in forwarded email")
                        for attachment in email_to_forward.attachments:
                            if attachment.file_name and attachment.file_contents:
                                self.logger.info(f"Adding attachment {attachment.file_name} from forwarded email")
                                # attachments_dict contains absolute file paths, email attachment contain only base names so no
                                # conflicts should occur
                                attachments_dict.update(attachment.to_dict())
                            else:
                                self.logger.error(f"Attachment of forwarded email failed to be loaded")

                    self.logger.info("Forwarding email..")

                    msg_id = self.email_smtp_manager.send_mail_html_embedded_photos(
                        to_addresses=self.send_to,
                        subject=self.subject,
                        html_body=self.build_forward_email_message(self.body, email_to_forward),
                        cc=self.cc,
                        bcc=self.bcc,
                        display_sender_name=self.display_sender_name,
                        attachments=attachments_dict
                    )

                    if self.return_msg_id:
                        message = "Mail forwarded successfully. Mail message id is: {}".format(msg_id)
                        self.logger.info("Saving result JSON")
                        json_result = {
                            "message_id": msg_id,
                            "date": utc_now(),
                            "recipients": self.send_to
                        }
                        self.siemplify.result.add_result_json(json_result)
                    else:
                        message = "Mail forwarded successfully."

                    output_messages.append(message)
                    self.logger.info(message)
                    return EXECUTION_STATE_COMPLETED, True

                except Exception as error:
                    message = "Failed to forward the email! Error is: {}".format(error)
                    self.logger.error(message)
                    self.logger.exception(error)
                    output_messages.append(message)

            except Exception as error:
                message = "Failed to forward the email! Error is: {}".format(error)
                self.logger.error("Unable to retrieve email with email_uid={0} from folder={1}".format(
                    email_uid, folder))
                self.logger.exception(error)

        if not email_to_forward_found:
            message = "Failed to find email to forward!"
            output_messages.append(message)
            self.logger.info(message)
        return EXECUTION_STATE_COMPLETED, False


@output_handler
def main():
    action = ForwardEmailAction()
    action.run()


if __name__ == "__main__":
    main()
