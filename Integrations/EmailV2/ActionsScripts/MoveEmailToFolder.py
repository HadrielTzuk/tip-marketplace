from EmailActions import EmailIMAPAction
from SiemplifyUtils import output_handler, utc_now
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT


class MoveEmailToFolderAction(EmailIMAPAction):
    """
    Searches for emails in the source folder, then moves emails matching the search criteria to the target folder.
    All Email mailbox manipulations are done via IMAP.
    """
    SCRIPT_NAME = "EmailV2 - Move Email To Folder"

    def __init__(self):
        """Override of the constructor to pass script name"""
        super(MoveEmailToFolderAction, self).__init__(MoveEmailToFolderAction.SCRIPT_NAME)

    # noinspection PyAttributeOutsideInit
    def load_action_configuration(self):
        """
        Overriding action configuration loading
        """
        folders_string = self._get_action_param(param_name="Source Folder Name",
                                                is_mandatory=True)
        self.folders = [f.strip() for f in folders_string.split(",") if f.strip()] if folders_string else []

        message_ids_string = self._get_action_param(param_name="Message IDs")
        self.message_ids = [m.strip() for m in message_ids_string.split(",") if m.strip()] if message_ids_string else []

        self.destination_folder = self._get_action_param(param_name="Destination Folder Name",
                                                         is_mandatory=True)
        self.subject = self._get_action_param(param_name="Subject Filter")
        self.unread = self._get_action_param(param_name="Only Unread",
                                             input_type=bool,
                                             default_value=False)

        if not self.message_ids and not self.subject:
            raise AttributeError("Both Message IDs and Subject Filter can't be empty")

    # noinspection PyUnusedLocal
    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Override of execution step. Searches for emails to move per each mailbox and moves them.
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Success flag: {bool} True - success, False - failure.
        """
        email_list = []
        for folder, email_uid in self.search_emails(
                folders=self.folders,
                message_ids=self.message_ids,
                subject=self.subject,
                only_unread=self.unread):
            try:
                self.logger.info("Moving email_uid={0} from {1} to {2} folder".format(
                    email_uid, folder, self.destination_folder))
                self.email_imap_manager.move_mail(
                    email_uid=email_uid,
                    source_folder=folder,
                    target_folder=self.destination_folder)
                self.logger.info("Successfully moved email")
                email_list.append(email_uid)
            except Exception as e:
                self.logger.error("Unable to move email_uid={0} from {1} to {2} folder".format(
                    email_uid, folder, self.destination_folder))
                self.logger.exception(e)

        message = "No mails were found matching the search criteria!"
        if email_list:
            message = "{0} mails were successfully moved from {1} to {2}".format(
                len(email_list),
                ", ".join(self.folders),
                self.destination_folder
            )

        output_messages.append(message)
        self.logger.info(message)
        return EXECUTION_STATE_COMPLETED, True


@output_handler
def main():
    action = MoveEmailToFolderAction()
    action.run()


if __name__ == "__main__":
    main()
