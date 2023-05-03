from datetime import timedelta

from EmailActions import EmailIMAPAction
from EmailCommon import build_json_result_from_emails_list

from ScriptResult import EXECUTION_STATE_COMPLETED
from SiemplifyUtils import output_handler, utc_now


class DeleteEmailAction(EmailIMAPAction):
    """
    Searches for emails in the mailbox, then deleted emails matching the search criteria.
    All Email mailbox manipulations are done via IMAP.
    """

    SCRIPT_NAME = "EmailV2 - Delete Email"

    def __init__(self):
        super(DeleteEmailAction, self).__init__(DeleteEmailAction.SCRIPT_NAME)

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

        self.subject = self._get_action_param(param_name="Subject Filter")
        self.sender = self._get_action_param(param_name="Sender Filter")
        self.recipient = self._get_action_param(param_name="Recipient Filter")
        self.delete_all = self._get_action_param(param_name="Delete All Matching Emails",
                                                 input_type=bool,
                                                 default_value=False)
        self.days_back = self._get_action_param(param_name="Days Back", input_type=int, default_value=None, is_mandatory=False)

        if not self.message_ids and (not self.subject and not self.sender and not self.recipient):
            raise AttributeError("Message IDs and Subject, Sender and Recipient filters can't be empty at the same time")

    # noinspection PyUnusedLocal
    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Override of execution step. Searches for emails to delete per each mailbox and deletes them.
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Success flag: {bool} True - success, False - failure.
        """
        email_list = []
        time_filter = None

        if isinstance(self.days_back, int):
            if self.days_back < 0:
                raise Exception("\"Days Back\" parameter must be non negative.")
            time_filter = utc_now() - timedelta(days=self.days_back)

        for folder, email_uid in self.search_emails(
                folders=self.folders,
                message_ids=self.message_ids,
                time_filter=time_filter,
                subject=self.subject,
                sender=self.sender,
                recipient=self.recipient):
            try:
                self.logger.info("Fetching email with email_uid={0} in folder={1}".format(
                    email_uid, folder))
                # We retrieve email contents and delete it at the same time
                email = self.email_imap_manager.get_message_data_by_message_id(
                    email_uid=email_uid,
                    folder_name=folder)

                if not email:
                    self.logger.info("No emails were found for email_uid={0} in folder={1}".format(
                        email_uid, folder))
                    continue
                self.logger.info("Fetched email successfully with email_uid={0} and message_id={1}".format(
                    email_uid, email.message_id))
                email_list.append((folder, email))
            except Exception as e:
                self.logger.error("Unable to retrieve email with email_uid={0} from folder={1}".format(
                    email_uid, folder))
                self.logger.exception(e)

        if not self.delete_all and email_list:
            email_list = email_list[:1]
            self.logger.info("Will delete just first email with email_uid={0} and message_id={1}".format(
                email_list[0][1].email_uid, email_list[0][1].message_id))

        for folder, email in email_list:
            try:
                self.email_imap_manager.delete_mail(email_uid=email.email_uid)
                self.logger.info("Deleted email with email_uid={0}".format(email.email_uid))
            except Exception as e:
                self.logger.error("Unable to delete email with email_uid={0} from folder={1}".format(
                    email.email_uid, folder))
                self.logger.exception(e)

        json_results = build_json_result_from_emails_list(email_list)
        self.siemplify.result.add_result_json(json_results)
        self.logger.info("Saved found emails as Action's JSON Results")

        message = "Failed to find emails for deletion!"
        if email_list:
            message = "{0} email(s) were deleted successfully".format(
                len(email_list))

        output_messages.append(message)
        self.logger.info(message)
        return EXECUTION_STATE_COMPLETED, True


@output_handler
def main():
    action = DeleteEmailAction()
    action.run()


if __name__ == "__main__":
    main()
