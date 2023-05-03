from EmailActions import EmailIMAPAction
from EmailFileManager import save_attachment_to_local_path
from SiemplifyUtils import output_handler, utc_now
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
import os


class DownloadEmailAttachmentsAction(EmailIMAPAction):
    """
    Searches for emails in the mailbox, downloads attachments from them into a dedicated folder.
    All Email mailbox manipulations are done via IMAP.
    """

    SCRIPT_NAME = "EmailV2 - Download Attachments"
    MAX_FILE_OUTPUT = 20

    def __init__(self):
        """
        Overriding common constructor
        """
        super(DownloadEmailAttachmentsAction, self).__init__(DownloadEmailAttachmentsAction.SCRIPT_NAME)

        if not os.path.exists(self.download_path):
            os.makedirs(self.download_path)

    # noinspection PyAttributeOutsideInit
    def load_action_configuration(self):
        """
        Overriding action configuration loading
        """
        folders_string = self._get_action_param(param_name="Folder Name",
                                                is_mandatory=True)
        self.folders = [f.strip() for f in folders_string.split(",") if f.strip()] if folders_string else []

        message_ids_string = self._get_action_param(param_name="Message IDs")
        self.message_ids = [m.strip() for m in message_ids_string.split(",") if m.strip()] if message_ids_string else []

        self.download_path = self._get_action_param(param_name="Download Path",
                                                    is_mandatory=True)
        self.subject = self._get_action_param(param_name="Subject Filter")

    # noinspection PyUnusedLocal
    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Override of execution step. Searches for emails and downloads their attachments to disk.
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Output value: {str} comma-separated list of downloaded attachments paths
        """
        attachments_local_paths = []
        for folder, email_uid in self.search_emails(
                folders=self.folders,
                message_ids=self.message_ids,
                subject=self.subject):
            try:
                self.logger.info("Fetching email with email_uid={0} in folder={1}".format(
                    email_uid, folder))
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

                email_path = os.path.join(self.download_path, email.get_trimmed_message_id())

                for attachment in email.attachments:
                    try:
                        # Save to given path
                        attachment_abs_path = save_attachment_to_local_path(
                            path=email_path,
                            attachment_name=attachment.file_name,
                            attachment_content=attachment.file_contents)
                        attachments_local_paths.append(attachment_abs_path)
                        self.logger.info("Saved email attachment {0} to the folder {1} for email_uid={2}".format(
                            attachment.file_name, self.download_path, email_uid))
                    except Exception as e:
                        self.logger.error("Unable to save attachment={0} from email_uid={1} to local_path={2}".format(
                            attachment.file_name, email_uid, self.download_path))
                        self.logger.exception(e)
            except Exception as e:
                self.logger.error("Unable to save attachments for email_uid={0} from folder={1}".format(
                    email_uid, folder))
                self.logger.exception(e)

        message = "No attachments found to download!"
        if attachments_local_paths:
            message = "Downloaded {0} attachments.\n\nTop-{1} Files:\n{2}".format(
                len(attachments_local_paths),
                self.MAX_FILE_OUTPUT,
                "\n".join(attachments_local_paths[:self.MAX_FILE_OUTPUT]))

        result_value = ",".join(attachments_local_paths)

        output_messages.append(message)
        self.logger.info(message)
        return EXECUTION_STATE_COMPLETED, result_value


@output_handler
def main():
    action = DownloadEmailAttachmentsAction()
    action.run()


if __name__ == "__main__":
    main()
