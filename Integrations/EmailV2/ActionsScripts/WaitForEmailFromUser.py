# -*- coding: utf-8 -*-
import json
import re
import arrow
import os
from datetime import timedelta
from SiemplifyUtils import utc_now, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_TIMEDOUT
from EmailCommon import safe_str_cast, save_attachments_to_case
from EmailActions import EmailIMAPAction
from EmailFileManager import save_attachments_locally


def should_response_be_excluded(email, body_exclude_pattern):
    """
    Get first message content from list which is not matching patterns.
    :param email: {dict} EmailModel object. Email body must be utf-8 encoded.
    :param body_exclude_pattern: {string} Subject regex exclude pattern.
    :return: {string} Relevant reply.
    """
    if not body_exclude_pattern:
        return False

    if email.body:
        # Message received as utf-8 encoded string - treated when receiving message.
        body_exclude_match = re.compile(body_exclude_pattern).match(email.body)
        if body_exclude_match:
            return True
    return False


class WaitForEmailFromUserAction(EmailIMAPAction):
    """
    This class should be used to await for responses to an email earlier sent by SendEmail action.
    WaitForEmailFromUser action should monitor target mailbox by IMAP for responses to email sent earlier.
    """

    SCRIPT_NAME = "EmailV2 - Wait for Email from User"

    CONF_IMAP_SERVER_ADDRESS = "IMAP Server Address"  # IMAP Server Address, e.g. imap.gmail.com
    CONF_IMAP_PORT = "IMAP Port"  # Port to connect to IMAP Server, e.g. 993
    CONF_IMAP_USE_SSL = "IMAP USE SSL"

    DEFAULT_RESOLVED_BODY = "Message Has No Body."
    DEFAULT_TIMEOUT_MESSAGE = "Timeout"

    def __init__(self):
        """
        WaitForEmailFromUserAction constructor.
        """
        super(WaitForEmailFromUserAction, self).__init__(WaitForEmailFromUserAction.SCRIPT_NAME)

    # noinspection PyAttributeOutsideInit
    def load_action_configuration(self):
        """
        Protected method, which should load configuration, specific to the SendEmail Action
        """
        self.timeout = self._get_action_param(param_name="Wait stage timeout (minutes)",
                                              input_type=int,
                                              default_value=1440)
        self.wait_for_all_recipients = self._get_action_param(param_name="Wait for all recipients to reply?",
                                                              input_type=bool)
        self.body_exclude_pattern = self._get_action_param(param_name="Wait stage exclude pattern")
        folders_string = self._get_action_param(param_name="Folder to check for reply",
                                                default_value="Inbox")
        self.folders = [f.strip() for f in folders_string.split(",") if f.strip()] if folders_string else []
        self.fetch_attachments = self._get_action_param(param_name="Fetch Response Attachments",
                                                        input_type=bool,
                                                        default_value=False)

        self.message_id = self._get_action_param(param_name="Email Message_id",
                                                 is_mandatory=True)
        email_date_string = self._get_action_param(param_name="Email Date",
                                                   is_mandatory=True)
        self.email_date = arrow.get(email_date_string) if email_date_string else arrow.utcnow()

        recipients_string = self._get_action_param(param_name="Email Recipients",
                                                   is_mandatory=True)
        if recipients_string:
            self.recipients = [address.strip() for address in recipients_string.split(",") if address.strip()]
        else:
            self.recipients = []
        if not self.recipients:
            raise AttributeError("Send Email recipients list can't be empty.")

    # noinspection PyUnusedLocal
    def execute_action(self, output_messages, successful_entities, failed_entities):
        """
        Pulls mailbox via IMAP to find email responses to email sent earlier
        :param output_messages: {list} Mutable list of output messages (str) to form audit trail for this action
        :param successful_entities: {list} N/A in case of SendEmail. List of entity.identifier's, which have been processed successfully
        :param failed_entities: {list} N/A in case of SendEmail. List of entity.identifier's, which have been failed during processing
        :return: {tuple} 1st value - Status of the operation: {int} 0 - success, 1 - failed, 2 - timed out; 2nd value - Success flag: {bool} True - success, False - failure.
        """
        email_list = []
        attachments = {}
        for folder, email_uid in self.search_emails(folders=self.folders, reply_to=self.message_id):
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
            email_list.append(email)

            if self.fetch_attachments:
                try:
                    attachments_paths = save_attachments_locally(self.siemplify.run_folder, email.attachments)
                    self.logger.info("Saved attachments locally for email_uid={}".format(email_uid))
                    attachments.update({email_uid: attachments_paths})
                except Exception as e:
                    self.logger.error("Unable to save attachments locally".format(
                        email_uid, folder))
                    self.logger.exception(e)

        self.siemplify.LOGGER.info(
            "Running on recipients: {0}, message ID: {1}".format(
                ",".join(self.recipients),
                self.message_id))
        recipients_responses = self.__find_email_per_recipient(email_list, self.recipients)
        self.logger.info("Gathered responses: {}".format([k for k, v in list(recipients_responses.items()) if v]))

        is_timeout = self.__is_timeout(self.recipients, recipients_responses)
        if is_timeout:
            self.logger.info("There are timed out responses")
            recipients_responses = self.__process_timeouts(self.recipients, recipients_responses)

        if self.fetch_attachments:
            save_attachments_to_case(self.siemplify, attachments)
            self.logger.info("Saved all attachments: {}".format(attachments))

        self.siemplify.result.add_result_json({"Responses": self.__construct_json_results(recipients_responses)})

        if is_timeout:
            message = "Timeout getting replies from users"
            output_messages.append(message)
            self.logger.info(message)
            return EXECUTION_STATE_TIMEDOUT, False
        elif not self.is_processing_completed(self.recipients, recipients_responses, self.wait_for_all_recipients):
            message = "Continuing...waiting for response, searching IN-REPLY-TO {0}".format(self.message_id)
            output_messages.append(message)
            self.logger.info(message)
            return EXECUTION_STATE_INPROGRESS, True
        else:
            message = u"Received all responses"
            output_messages.append(message)
            self.logger.info(message)
            return EXECUTION_STATE_COMPLETED, True

    def __is_timeout(self, recipients, recipients_responses):
        """
        Identifies if there are any missing & timed out responses
        :param recipients: {list} List of recipient email addresses
        :param recipients_responses: {dict} Dictionary with all available and valid (not OOO) responses from the email recipients
        :return: True - in case of any responses are missing and timeout. False - otherwise.
        """
        if self.email_date + timedelta(minutes=self.timeout) < utc_now():
            are_responses_missing = False
            for r in recipients:
                if not recipients_responses.get(r):
                    are_responses_missing = True
                    break
            if are_responses_missing:
                return True

        return False

    def __process_timeouts(self, recipients, recipients_responses):
        """
        Updates all timeout responses with default message
        :param recipients: {list} List of recipient email addresses
        :param recipients_responses: {dict} Dictionary with all available and valid (not OOO) responses from the email recipients
        :return: {dict} Updated responses dictionary with time out messages
        """
        responses = dict(recipients_responses)

        if self.email_date + timedelta(minutes=self.timeout) < utc_now():
            for r in recipients:
                if not responses.get(r):
                    self.logger.info("Timeout getting reply from user: {0}".format(r))
                    responses[r] = self.DEFAULT_TIMEOUT_MESSAGE

        return responses

    def is_processing_completed(self, recipients, recipients_responses, wait_for_all_recipients):
        """
        Identifies if email processing has been completed
        :param recipients: {list} List of recipient email addresses
        :param recipients_responses: {dict} Dictionary with all available and valid (not OOO) responses from the email recipients
        :param wait_for_all_recipients: {bool} In some cases just first response from the any recipient is enough. If this is the case, then this parameter should be True.
        :return: True - we have successfully received all the responses. False - otherwise.
        """
        def __is_one_response_at_least():
            for r in recipients:
                response = recipients_responses.get(r)
                if response and response != self.DEFAULT_TIMEOUT_MESSAGE:
                    return True
            return False

        def __is_full_response():
            for r in recipients:
                if not recipients_responses.get(r):
                    return False
                elif recipients_responses.get(r) == self.DEFAULT_TIMEOUT_MESSAGE:
                    return False
            return True

        if not wait_for_all_recipients:
            return __is_one_response_at_least()

        return __is_full_response()

    def __find_email_per_recipient(self, emails_list, recipients_list):
        """
        Reviews list of emails found on the server and maps each to a recipient from the list
        :param emails_list: {list} List of EmailModel objects
        :param recipients_list: {list} List of recipient emails
        :return: {dict} Map of recipients responses.
        """
        recipients_responses = {}

        for recipient in recipients_list:
            self.logger.info(
                "Running on recipient: {0}".format(recipient))

            email = self.__get_user_first_valid_message(
                sender=recipient,
                emails_list=emails_list,
                body_exclude_pattern=self.body_exclude_pattern)

            if email and email.body:
                self.logger.info(
                    "Got email for recipient: {0}".format(recipient))
                recipients_responses[recipient] = email.body
            else:
                recipients_responses[recipient] = None

        return recipients_responses

    def __get_user_first_valid_message(self,
                                       sender,
                                       emails_list,
                                       body_exclude_pattern=None):
        """
        Get all messages sent by recipient.
        :param sender: {string} Sender address.
        :param email_list: {list} List of EmailModel objects
        :param body_exclude_pattern: {string} subject regex exclude pattern.
        :return: {list} list of relevant message dicts.
        """
        if not emails_list or len(emails_list) == 0:
            return None

        senders_messages = [message for message in emails_list if
                            message.last_email_sender.lower() == sender.lower()]

        self.logger.info("Found {0} messages for sender {1}".format(len(senders_messages), sender))

        try:
            senders_messages = sorted(senders_messages, key=lambda i: i.email_date)
        except Exception as err:
            self.logger.error("Messages does not contain date key.")
            self.logger.exception(err)

        for sequence, message in enumerate(senders_messages):
            self.logger.info(
                'Checking message match exclude pattern for sender: {0}, message sequence:{1}'.format(sender,
                                                                                                      sequence + 1))
            if not should_response_be_excluded(message, body_exclude_pattern):
                self.logger.info("Message in sequence {0} for sender {1} is valid.".format(sequence + 1, sender))
                return message
            else:
                self.logger.info("Message in sequence {0} for sender {1} is not valid.".format(sequence + 1, sender))
                continue
        return None

    def __build_result_objects(self, email):
        """
        Generate output message from received email.
        output_message should be first email body (full thread) + handle unicode/str encoding as needed
        :param message: {EmailModel} Received message dict.
        :return: {tuple} Action output and result value.
        """
        body = email.body if email.body else self.DEFAULT_RESOLVED_BODY
        body = safe_str_cast(body, self.DEFAULT_RESOLVED_BODY)

        try:
            # Extract response content without the forwarding part
            result_value = body[:(body.index('<'))]
        except Exception as e:
            self.logger.error("Failed to extract response content without the forwarding part")
            self.logger.exception(str(e))
            result_value = body

        output_message = "Response:\n{0}".format(body)

        return output_message, result_value

    def __construct_json_results(self, recipients_responses):
        """
        Create a JSON results object out of the recipients responses
        :param recipients_responses: {dict} The recipients responses
        :return: {list} The constructed JSON results
        """
        json_results = []

        for recipient, response in list(recipients_responses.items()):
            json_results.append({
                "recipient": recipient,
                "content": response
            })

        return json_results

@output_handler
def main():
    action = WaitForEmailFromUserAction()
    action.run()


if __name__ == "__main__":
    main()
