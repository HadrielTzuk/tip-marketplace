import json
import re
from ExchangeActions import extract_action_parameter, init_manager
from ExchangeCommon import ExchangeCommon
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED, \
    EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, utc_now, unix_now
import sys
from constants import INTEGRATION_NAME, WAIT_FOR_VOTE_MAIL_RESULTS_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER, \
    EMAIL_REGEX
from datetime import timedelta, datetime, timezone
from exceptions import GetUserReplyException
from exceptions import IncompleteInfoException, NotFoundEmailsException


# Constants
DEFAULT_TIMEOUT_MESSAGE = "Timeout"
ITERATIONS_INTERVAL = 30 * 1000
ITERATION_DURATION_BUFFER = 60 * 1000

# maximum retry count in case of network error
MAX_RETRY = 5
ACTION_START_TIME = datetime.timestamp(datetime.utcnow().replace(tzinfo=timezone.utc))


def query_responses(siemplify, manager, message_id, sent_mail_folders, replies_folders, recipients,
                    timeout_in_minutes, wait_for_all_recipients,
                    action_start_time):
    """
    Get mail replies by provided data.
    :param siemplify: SiemplifyAction object.
    :param manager: ExchangeManager object.
    :param message_id: {str} Specifies message_id which responses should be fetched.
    :param sent_mail_folders: {list} Folder names to search for sent mail.
    :param replies_folders: {list} Folder names to search for replies.
    :param recipients: {list} List of recipients.
    :param timeout_in_minutes: {int} Minutes to specify timeout.
    :param wait_for_all_recipients: {bool} Specifies should action wait for all recipients responses or no.
    :param action_start_time: {int} Action first iteration start time timestamp
    :return: {tuple} output message, json result, execution state.
    """
    responses = []
    original_mails = []
    recipients_responses = {}
    ec = ExchangeCommon(siemplify.LOGGER, manager)

    for sent_mail_folder in sent_mail_folders:
        original_mails = manager.receive_mail(message_id=message_id, folder_name=sent_mail_folder)

        if original_mails:
            break

    original_mail = original_mails[0] if original_mails else None

    if not original_mail:
        raise NotFoundEmailsException

    for replies_folder in replies_folders:
        conversation_items = manager.receive_mail(conversation_id=original_mail.conversation_id, siemplify_result=True,
                                                  folder_name=replies_folder)
        responses.extend([conversation_item for conversation_item in conversation_items
                          if conversation_item.get('message_id') != message_id])

    if not responses:
        siemplify.LOGGER.info("Replies not found, continuing waiting...")
    else:
        siemplify.LOGGER.info("Received {} replies.".format(len(responses)))
        siemplify.LOGGER.info("Running on recipients: {}".format(PARAMETERS_DEFAULT_DELIMITER.join(recipients)))

        for recipient in recipients:
            try:
                message = ec.get_user_first_valid_message(sender=recipient, messages=responses)
                recipients_responses[recipient] = message

            except Exception as e:
                raise GetUserReplyException("Failed to get user {} reply, the error is: {}".format(recipient, e))

    json_result = recipients_responses

    if is_processing_completed(recipients, recipients_responses, wait_for_all_recipients):
        result_value = True
        status = EXECUTION_STATE_COMPLETED
        output_message = build_output_message(recipients_responses)
    elif is_timeout(action_start_time, timeout_in_minutes):
        json_result, output_message = handle_timeout_results(recipients, recipients_responses)
        result_value = False
        status = EXECUTION_STATE_TIMEDOUT
    else:
        result_value = json.dumps({
            "action_start_time": action_start_time,
            "recipients_responses": recipients_responses
        })
        status = EXECUTION_STATE_INPROGRESS
        output_message = "Continuing waiting for replies, searching IN-REPLY-TO {}".format(message_id)
        output_message += "\nGot response from {} out of {} recipients so far".format(
            len(responses),
            len(recipients)
        )

    if json_result:
        siemplify.result.add_result_json({"Responses": construct_json_results(json_result)})

    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = WAIT_FOR_VOTE_MAIL_RESULTS_SCRIPT_NAME
    mode = "Main" if is_first_run else "QueryState"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    # Action parameters
    message_id = extract_action_parameter(siemplify=siemplify, param_name="Vote Mail message_id", is_mandatory=True)
    sent_mail_folder_names = extract_action_parameter(siemplify=siemplify, param_name="Folder to check for Sent Mail",
                                                      is_mandatory=True)
    replies_folder_names = extract_action_parameter(siemplify=siemplify, param_name="Folder to Check for Reply",
                                                    is_mandatory=True)
    recipients_string = extract_action_parameter(siemplify=siemplify, param_name="Mail Recipients", is_mandatory=True)
    timeout_in_minutes = extract_action_parameter(siemplify=siemplify, input_type=int,
                                                  param_name="How long to wait for recipient reply (minutes)",
                                                  is_mandatory=True)
    wait_for_all_recipients = extract_action_parameter(siemplify=siemplify, input_type=bool,
                                                       param_name="Wait for All Recipients to Reply?")

    mail_recipients = [recipient.strip() for recipient in recipients_string.split(PARAMETERS_DEFAULT_DELIMITER)
                       if recipient.strip()] if recipients_string else []

    sent_mail_folders = [folder.strip() for folder in sent_mail_folder_names.split(PARAMETERS_DEFAULT_DELIMITER)
                         if folder.strip()] if sent_mail_folder_names else []
    replies_folders = [folder.strip() for folder in replies_folder_names.split(PARAMETERS_DEFAULT_DELIMITER)
                       if folder.strip()] if replies_folder_names else []

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    try:
        valid_recipients = [recipient for recipient in mail_recipients if re.search(EMAIL_REGEX, recipient)]
        invalid_recipients = list(set(mail_recipients) - set(valid_recipients))

        if not valid_recipients:
            raise IncompleteInfoException

        additional_data = json.loads(siemplify.parameters.get("additional_data")) \
            if siemplify.parameters.get("additional_data") else {}
        # Check if script timeout approaching
        if is_script_timeout(siemplify):
            responses = additional_data.get("recipients_responses")
            json_result, output_message = handle_timeout_results(valid_recipients, responses)
            if json_result:
                siemplify.result.add_result_json({"Responses": construct_json_results(json_result)})
            result_value = False
            status = EXECUTION_STATE_TIMEDOUT
        else:
            # Create new exchange manager instance
            manager = init_manager(siemplify, INTEGRATION_NAME)

            if is_first_run:
                output_message, result_value, status = query_responses(
                    siemplify=siemplify,
                    manager=manager,
                    message_id=message_id,
                    sent_mail_folders=sent_mail_folders,
                    replies_folders=replies_folders,
                    recipients=valid_recipients,
                    timeout_in_minutes=timeout_in_minutes,
                    wait_for_all_recipients=wait_for_all_recipients,
                    action_start_time=ACTION_START_TIME
                )
            else:
                output_message, result_value, status = query_responses(
                    siemplify=siemplify,
                    manager=manager,
                    message_id=message_id,
                    sent_mail_folders=sent_mail_folders,
                    replies_folders=replies_folders,
                    recipients=valid_recipients,
                    timeout_in_minutes=timeout_in_minutes,
                    wait_for_all_recipients=wait_for_all_recipients,
                    action_start_time=additional_data.get("action_start_time")
                )

        if invalid_recipients:
            output_message += f"\nCould not perform action on the following mailboxes: " \
                              f"{PARAMETERS_DEFAULT_DELIMITER.join(invalid_recipients)}"

    except NotFoundEmailsException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Could not find email with Message Id - {} in {} folders".format(message_id,
                                                                                          sent_mail_folder_names)
    except IncompleteInfoException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Could not perform action on any of the provided mailboxes. Please check the action " \
                         "parameters and try again"
    except GetUserReplyException as e:
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = e
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(WAIT_FOR_VOTE_MAIL_RESULTS_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Failed to execute action, the error is: {}".format(e)
        additional_data_json = extract_action_parameter(siemplify=siemplify, param_name="additional_data",
                                                        default_value='{}')
        output_message, result_value, status = ExchangeCommon.prevent_async_action_fail_in_case_of_network_error(
            e,
            additional_data_json,
            MAX_RETRY,
            output_message,
            result_value,
            status)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


def is_timeout(action_start_time, timeout_in_minutes):
    """
    Check if action times out
    :param action_start_time: {int} Action first iteration start time timestamp
    :param timeout_in_minutes: {int} Minutes to specify timeout
    :return: {bool} True - if action timed out, False - otherwise
    """
    return datetime.utcfromtimestamp(action_start_time) + timedelta(minutes=timeout_in_minutes) < datetime.utcnow()


def is_script_timeout(siemplify):
    """
    Check if script timeout approaching
    :param siemplify: SiemplifyAction object
    :return: {bool} True - if timeout approaching, False - otherwise
    """
    return unix_now() + ITERATION_DURATION_BUFFER + ITERATIONS_INTERVAL >= siemplify.execution_deadline_unix_time_ms


def set_timeouts_for_responses(recipients, recipients_responses):
    """
    Updates all timeout responses with default message
    :param recipients: {list} List of recipients
    :param recipients_responses: {dict} All fetched and valid responses from the email recipients
    :return: {dict} Updated responses with timeout messages
    """
    for recipient in recipients:
        if not recipients_responses.get(recipient):
            recipients_responses[recipient] = DEFAULT_TIMEOUT_MESSAGE

    return recipients_responses


def is_processing_completed(recipients, recipients_responses, wait_for_all_recipients):
    """
    Identifies if processing has been completed
    :param recipients: {list} List of recipients
    :param recipients_responses: {dict} All fetched and valid responses from the email recipients
    :param wait_for_all_recipients: {bool} Specifies should action wait for all recipients responses or no.
    :return: {bool} True - if process completed, False - otherwise.
    """
    number_of_valid_responses = len([recipient for recipient in recipients if recipients_responses.get(recipient)])

    if wait_for_all_recipients:
        return number_of_valid_responses == len(recipients)

    return number_of_valid_responses


def construct_json_results(recipients_responses):
    """
    Create a JSON results object out of the recipients responses
    :param recipients_responses: {dict} All fetched and valid responses from the email recipients
    :return: {list} The JSON results
    """
    json_results = []

    for recipient, response in recipients_responses.items():
        if response:
            json_results.append({
                "recipient": recipient,
                "vote": response if isinstance(response, str) else response.get("vote_response")
            })

    return json_results


def build_output_message(recipients_responses):
    """
    Build Output message string
    :param recipients_responses: {dict} All recipients responses
    :return: {str} The output message.
    """
    output_message = ""

    for recipient, response in recipients_responses.items():
        if response == DEFAULT_TIMEOUT_MESSAGE:
            output_message += "Timeout getting reply from user: {}\n".format(recipient)
        elif response:
            output_message += "Found the user {} reply\n".format(recipient)

    return output_message


def handle_timeout_results(recipients, recipients_responses):
    """
    Prepare action results in case of timeout
    :param recipients: {list} List of recipients.
    :param recipients_responses: {dict} The recipients responses
    :return: {tuple} json_result, output_message
    """
    recipients_responses = set_timeouts_for_responses(recipients, recipients_responses)
    json_result = recipients_responses
    output_message = build_output_message(recipients_responses)
    return json_result, output_message


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
