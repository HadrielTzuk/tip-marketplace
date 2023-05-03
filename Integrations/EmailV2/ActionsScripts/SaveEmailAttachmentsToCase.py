from EmailActions import EmailIMAPAction
from EmailCommon import build_json_result_from_emails_list, save_attachments_to_case
from EmailFileManager import save_attachments_locally
from SiemplifyUtils import output_handler, utc_now
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT


def filter_attachments_by_name(attachments_list, attachment_name):
    # type: (list, str) -> list
    """
    Filters attachments list by a specific attachment name
    :param attachments_list: {list} List of EmailAttachmentModel objects
    :param attachment_name: {str} Name of the attachment file name to look for
    :return: {list} List of filtered EmailAttachmentModel objects
    """
    new_attachments = []
    for attachment in attachments_list:
        if attachment.file_name == attachment_name:
            new_attachments.append(attachment)
    return new_attachments


class SaveEmailAttachmentsToCaseAction(EmailIMAPAction):
    """
    Searches for emails in the mailbox, then saves attachments to the case
    for emails matching the search criteria.
    All Email mailbox manipulations are done via IMAP.
    """

    SCRIPT_NAME = "EmailV2 - Save Email Attachments To Case"

    def __init__(self):
        """
        Overriding of the constructor
        """
        super(SaveEmailAttachmentsToCaseAction, self).__init__(SaveEmailAttachmentsToCaseAction.SCRIPT_NAME)

    # noinspection PyAttributeOutsideInit
    def load_action_configuration(self):
        """
        Overriding action configuration loading
        """
        folders_string = self._get_action_param(param_name="Folder Name",
                                                is_mandatory=True)
        self.folders = [f.strip() for f in folders_string.split(",") if f.strip()] if folders_string else []

        self.message_id = self._get_action_param(param_name="Message ID")
        self.attachment_name = self._get_action_param(param_name="Attachment To Save")

    # noinspection PyUnusedLocal
    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Override of execution step. Searches for emails to download their attachments and attaches them to the case.
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Success flag: {bool} True - success, False - failure.
        """
        email_list = []
        attachments = {}
        message_ids = [self.message_id] if self.message_id else []
        for folder, email_uid in self.search_emails(folders=self.folders, message_ids=message_ids):
            try:
                self.logger.info("Fetching email with email_uid={0} in folder={1}".format(
                    email_uid, folder))
                # We retrieve email contents and delete it at the same time
                email = self.email_imap_manager.get_message_data_by_message_id(
                    email_uid=email_uid,
                    folder_name=folder,
                    mark_as_read=True)
                if not email:
                    self.logger.info("No emails were found for email_uid={0} in folder={1}".format(
                        email_uid, folder))
                    continue
                self.logger.info("Fetched email successfully with email_uid={0} and message_id={1}".format(
                    email_uid, email.message_id))

                email_list.append((folder, email))
                mail_attachments = email.attachments
                if self.attachment_name:
                    self.logger.info("Filtering attachments by name: {}".format(self.attachment_name))
                    mail_attachments = filter_attachments_by_name(email.attachments, self.attachment_name)

                self.logger.info("Saving attachments locally for email_uid={}".format(email_uid))
                attachments_paths = save_attachments_locally(self.siemplify.run_folder, mail_attachments)

                attachments.update({email_uid: attachments_paths})
            except Exception as e:
                self.logger.error("Unable to fetch attachments for email_uid={0} from folder={1}".format(
                    email_uid, folder))
                self.logger.exception(e)

        num_emails, num_files = save_attachments_to_case(self.siemplify, attachments)
        self.logger.info("Saved all attachments to the case")

        json_results = build_json_result_from_emails_list(email_list)
        self.siemplify.result.add_result_json(json_results)

        message = "No attachments have been found!"
        if attachments:
            message = "Saved {0} files from {1} emails".format(num_files, num_emails)

        output_messages.append(message)
        self.logger.info(message)
        return EXECUTION_STATE_COMPLETED, True


@output_handler
def main():
    action = SaveEmailAttachmentsToCaseAction()
    action.run()


if __name__ == "__main__":
    main()
