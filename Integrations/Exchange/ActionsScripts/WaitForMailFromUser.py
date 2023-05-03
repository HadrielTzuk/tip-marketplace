import json
from ExchangeActions import extract_action_parameter, init_manager
from ExchangeManager import SiemplifyMessageDictKeys
from ExchangeCommon import ExchangeCommon
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED, \
    EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler, utc_now, unix_now
import sys
from constants import INTEGRATION_NAME, WAIT_FOR_MAIL_FROM_USER_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER
from datetime import timedelta, datetime
from exceptions import GetUserReplyException


# Constants
DEFAULT_TIMEOUT_MESSAGE = "Timeout"
ITERATIONS_INTERVAL = 30 * 1000
ITERATION_DURATION_BUFFER = 60 * 1000

# maximum retry count in case of network error
MAX_RETRY = 5


def query_responses(siemplify, manager, message_id, mail_date, folders, recipients, timeout_in_minutes,
                    wait_for_all_recipients, wait_stage_exclude_pattern, fetch_response_attachments):
    """
    Get mail replies by provided data.
    :param siemplify: SiemplifyAction object.
    :param manager: ExchangeManager object.
    :param message_id: {str} Specifies message_id which responses should be fetched.
    :param mail_date: {int} Specifies timestamp of the mail for which responses should be fetched.
    :param folders: {list} List of folders to search for responses.
    :param recipients: {list} List of recipients.
    :param timeout_in_minutes: {int} Minutes to specify timeout.
    :param wait_for_all_recipients: {bool} Specifies should action wait for all recipients responses or no.
    :param wait_stage_exclude_pattern: {str} Regular expression to exclude specific responses.
    :param fetch_response_attachments: {bool} Specifies should action fetch responses attachments or no.
    :return: {tuple} output message, json result, execution state.
    """
    responses = []
    recipients_responses = {}
    ec = ExchangeCommon(siemplify.LOGGER, manager)

    for folder in folders:
        siemplify.LOGGER.info("Searching replies in folder {}.".format(folder))
        responses.extend(manager.receive_mail(reply_to=message_id, siemplify_result=True, folder_name=folder))

    if not responses:
        siemplify.LOGGER.info("Replies not found, continuing waiting...")
    else:
        siemplify.LOGGER.info("Received {} replies.".format(len(responses)))
        siemplify.LOGGER.info("Running on recipients: {}".format(PARAMETERS_DEFAULT_DELIMITER.join(recipients)))

        for recipient in recipients:
            try:
                message = ec.get_user_first_valid_message(sender=recipient, messages=responses,
                                                          body_exclude_pattern=wait_stage_exclude_pattern)
                recipients_responses[recipient] = message

                if message and fetch_response_attachments:
                    try:
                        message_attachments = message.get(SiemplifyMessageDictKeys.ATTACHMENTS_KEY, {})
                        siemplify.LOGGER.info("Found {} attachments".format(len(message_attachments)))

                        for file_name, file_content in list(message_attachments.items()):
                            siemplify.result.add_attachment(title="recipient {} reply attachment".format(recipient),
                                                            filename="{}".format(file_name),
                                                            file_contents=file_content)
                            siemplify.LOGGER.info("Attached file with name '{}'".format(file_name))
                    except Exception as err:
                        error_message = "Failed fetching attachments for user {} reply.".format(recipient)
                        siemplify.LOGGER.error(error_message)
                        siemplify.LOGGER.exception(err)

            except Exception as e:
                raise GetUserReplyException("Failed to get user {} reply, the error is: {}".format(recipient, e))

    json_result = recipients_responses

    if is_processing_completed(recipients, recipients_responses, wait_for_all_recipients):
        result_value = True
        status = EXECUTION_STATE_COMPLETED
        output_message = build_output_message(recipients_responses)
    elif is_timeout(mail_date, timeout_in_minutes):
        json_result, output_message = handle_timeout_results(recipients, recipients_responses)
        result_value = False
        status = EXECUTION_STATE_TIMEDOUT
    else:
        result_value = json.dumps(recipients_responses)
        status = EXECUTION_STATE_INPROGRESS
        output_message = "Continuing waiting for replies, searching IN-REPLY-TO {}".format(message_id)

    if json_result:
        siemplify.result.add_result_json({"Responses": construct_json_results(json_result)})

    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = WAIT_FOR_MAIL_FROM_USER_SCRIPT_NAME
    mode = "Main" if is_first_run else "QueryState"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    # Action parameters
    message_id = extract_action_parameter(siemplify=siemplify, param_name="Mail message_id", is_mandatory=True)
    mail_date = extract_action_parameter(siemplify=siemplify, param_name="Mail Date", is_mandatory=True, input_type=int)
    recipients_string = extract_action_parameter(siemplify=siemplify, param_name="Mail Recipients", is_mandatory=True)
    timeout_in_minutes = extract_action_parameter(siemplify=siemplify, input_type=int,
                                                  param_name="How long to wait for recipient reply (minutes)",
                                                  is_mandatory=True)
    wait_for_all_recipients = extract_action_parameter(siemplify=siemplify, input_type=bool,
                                                       param_name="Wait for All Recipients to Reply?")
    wait_stage_exclude_pattern = extract_action_parameter(siemplify=siemplify, param_name="Wait Stage Exclude pattern")
    reply_folders_string = extract_action_parameter(siemplify=siemplify, param_name="Folder to Check for Reply")
    fetch_response_attachments = extract_action_parameter(siemplify=siemplify, input_type=bool,
                                                          param_name="Fetch Response Attachments")

    mail_recipients = [recipient.strip() for recipient in recipients_string.split(PARAMETERS_DEFAULT_DELIMITER)
                       if recipient.strip()] if recipients_string else []
    reply_folders = [folder.strip() for folder in reply_folders_string.split(PARAMETERS_DEFAULT_DELIMITER)
                     if folder.strip()] if reply_folders_string else []

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    try:
        # Check if script timeout approaching
        if is_script_timeout(siemplify):
            responses = json.loads(siemplify.parameters["additional_data"])
            json_result, output_message = handle_timeout_results(mail_recipients, responses)
            if json_result:
                siemplify.result.add_result_json({"Responses": construct_json_results(json_result)})
            result_value = False
            status = EXECUTION_STATE_TIMEDOUT
        else:
            # Create new exchange manager instance
            manager = init_manager(siemplify, INTEGRATION_NAME)

            output_message, result_value, status = query_responses(
                siemplify=siemplify,
                manager=manager,
                message_id=message_id,
                mail_date=mail_date,
                folders=reply_folders,
                recipients=mail_recipients,
                timeout_in_minutes=timeout_in_minutes,
                wait_for_all_recipients=wait_for_all_recipients,
                wait_stage_exclude_pattern=wait_stage_exclude_pattern,
                fetch_response_attachments=fetch_response_attachments
            )

    except GetUserReplyException as e:
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = e
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(WAIT_FOR_MAIL_FROM_USER_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Failed to execute action, the error is: {}".format(e)
        additional_data_json = extract_action_parameter(siemplify=siemplify, param_name="additional_data",
                                                        default_value='{}')
        output_message, result_value, status = ExchangeCommon.prevent_async_action_fail_in_case_of_network_error(e,
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


def is_timeout(mail_date, timeout_in_minutes):
    """
    Check if action times out
    :param mail_date: {int} Specifies timestamp of the mail for which responses should be fetched.
    :param timeout_in_minutes: {int} Minutes to specify timeout.
    :return: {bool} True - if action timed out, False - otherwise.
    """
    return datetime.utcfromtimestamp(mail_date) + timedelta(minutes=timeout_in_minutes) < datetime.utcnow()


def is_script_timeout(siemplify):
    """
    Check if script timeout approaching
    :param siemplify: SiemplifyAction object.
    :return: {bool} True - if timeout approaching, False - otherwise.
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
                "content": response
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
