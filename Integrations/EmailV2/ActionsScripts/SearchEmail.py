from datetime import timedelta
from EmailActions import EmailIMAPAction
from EmailCommon import build_json_result_from_emails_list
from SiemplifyUtils import output_handler, utc_now
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT


class SearchEmailAction(EmailIMAPAction):
    """
    This class represents SearchEmailAction. SearchEmailAction searches target mail via IMAP
    by configurable criteria and returns found emails as a JSON.
    This action doesn't support any retry logic.
    """

    SCRIPT_NAME = "EmailV2 - Search Email"

    DEFAULT_OFFSET_IN_MINUTES = None

    def __init__(self):
        """
        SearchEmailAction constructor. Loads integration configuration and initializes EmailIMAPManager instance
        """
        super(SearchEmailAction, self).__init__(SearchEmailAction.SCRIPT_NAME)

    # noinspection PyAttributeOutsideInit
    def load_action_configuration(self):
        """
        Protected method, which should load configuration, specific to the SearchEmail Action
        """
        folders_string = self._get_action_param(param_name="Folder Name",
                                                is_mandatory=True)
        self.folders = [f.strip() for f in folders_string.split(",") if f.strip()] if folders_string else []
        self.subject = self._get_action_param(param_name="Subject Filter")
        self.sender = self._get_action_param(param_name="Sender Filter")
        self.recipient = self._get_action_param(param_name="Recipient Filter")
        self.offset_in_minutes = self._get_action_param(param_name="Time frame (minutes)",
                                                        input_type=int, default_value=60)
        self.unread_only = self._get_action_param(param_name="Only Unread",
                                                  input_type=bool,
                                                  default_value=False)
        self.max_emails = self._get_action_param(param_name="Max Emails To Return",
                                                 input_type=int,
                                                 default_value=100)

    # noinspection PyUnusedLocal
    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Searches for Email with all configured criteria
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} N/A in case of SearchEmail. List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Success flag: {bool} True - success, False - failure.
        """
        email_list = []
        counter = 0
        time_filter = utc_now() - timedelta(minutes=self.offset_in_minutes)
        for folder, email_uid in self.search_emails(
                folders=self.folders,
                message_ids=[],
                time_filter=time_filter,
                subject=self.subject,
                sender=self.sender,
                recipient=self.recipient,
                only_unread=self.unread_only):
            try:
                if counter >= self.max_emails:
                    self.logger.info("Search reached limit of {0} emails".format(self.max_emails))
                    break

                self.logger.info("Fetching email with email_uid={0} in folder={1}".format(
                    email_uid, folder))
                email = self.email_imap_manager.get_message_data_by_message_id(
                        email_uid=email_uid,
                        folder_name=folder,
                )
                if not email:
                    self.logger.info("No emails were found for email_uid={0} in folder={1}".format(
                        email_uid, folder))
                    continue
                self.logger.info("Fetched email with email_uid={0} and message_id={1}".format(
                    email_uid, email.message_id))
                email_list.append((folder, email))
                counter += 1
            except Exception as e:
                self.logger.error("Unable to retrieve email with email_uid={0} from folder={1}".format(
                    email_uid, folder))
                self.logger.exception(e)

        json_results = build_json_result_from_emails_list(email_list)
        self.siemplify.result.add_result_json(json_results)

        message = "Search didn't found any matching emails"
        if email_list:
            message = "Search found {0} emails based on the provided search criteria".format(
                len(email_list))

        output_messages.append(message)
        self.logger.info(message)
        return EXECUTION_STATE_COMPLETED, True


@output_handler
def main():
    action = SearchEmailAction()
    action.run()


if __name__ == "__main__":
    main()
