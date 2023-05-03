import sys
import json
import pytz
from datetime import timedelta
from ExchangeActions import extract_action_parameter, init_manager
from ExchangeCommon import ExchangeCommon
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED, \
    EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, utc_now, unix_now
from constants import INTEGRATION_NAME, UNBLOCK_SENDER_BY_MESSAGE_ID_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER, \
    MAILBOX_DEFAULT_LIMIT
from exceptions import NotFoundEmailsException, NotSupportedVersionException, TimeoutException
from exchangelib.version import EXCHANGE_2013


# Constants
ITERATIONS_INTERVAL = 30 * 1000
ITERATION_DURATION_BUFFER = 60 * 1000
MAX_RETRY = 5  # maximum retry count in case of network error


def not_junk_mail(logger, manager, move_items, message_ids, mailboxes, folder_names, subject_filter, from_filter,
                  recipient_filter, mark_all_matching_emails, time_filter):
    """
    Find messages and mark them as not junk
    :param logger: {SiemplifyLogger} SiemplifyLogger object.
    :param manager: {ExchangeManager} ExchangeManager object
    :param move_items: {bool} Specifies whether move messages to the inbox folder or no
    :param message_ids: {list} The message ids which should be not junked
    :param mailboxes: {list} The list of mailboxes to search for messages
    :param folder_names: {list} The list of folders to search for messages.
    :param subject_filter: {str} Filter by subject
    :param from_filter: {str} Filter by sender
    :param recipient_filter: {str} Filter by recipient
    :param mark_all_matching_emails: {bool} Mark all suitable messages or only the first
    :param time_filter: {datetime} Filter by time
    :return: {tuple} successful_messages, failed_mailboxes
    """
    failed_mailboxes = []
    successful_messages = []

    for mailbox in mailboxes:
        try:
            logger.info(f"Processing {mailbox} mailbox ")

            if message_ids:
                for message_id in message_ids:
                    try:
                        successful_messages.extend(manager.junk_mail(
                            mailbox_address=mailbox,
                            is_junk=False,
                            move_items=move_items,
                            folder_names=folder_names,
                            message_id=message_id,
                            mark_all_matching_emails=mark_all_matching_emails,
                            time_filter=time_filter
                        ))

                    except Exception as e:
                        logger.error(f"Failed to mark messages as not junk from mailbox {mailbox}.")
                        logger.exception(e)
                        failed_mailboxes.append(mailbox)

            else:
                successful_messages.extend(manager.junk_mail(
                    mailbox_address=mailbox,
                    is_junk=False,
                    move_items=move_items,
                    folder_names=folder_names,
                    subject_filter=subject_filter,
                    from_filter=from_filter,
                    recipient_filter=recipient_filter,
                    mark_all_matching_emails=mark_all_matching_emails,
                    time_filter=time_filter
                ))

        except Exception as e:
            logger.error(f"Failed to mark messages as not junk from mailbox {mailbox}.")
            logger.exception(e)
            failed_mailboxes.append(mailbox)

    return successful_messages, list(set(failed_mailboxes))


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = UNBLOCK_SENDER_BY_MESSAGE_ID_SCRIPT_NAME
    mode = "Main" if is_first_run else "QueryState"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    # Action parameters
    move_items = extract_action_parameter(siemplify=siemplify, param_name="Move items back to Inbox?", is_mandatory=True,
                                          input_type=bool, print_value=True)
    message_ids_string = extract_action_parameter(siemplify=siemplify, param_name="Message IDs", print_value=True)
    mailboxes_string = extract_action_parameter(siemplify=siemplify, param_name="Mailboxes list to perform on",
                                                print_value=True)
    folder_names_string = extract_action_parameter(siemplify=siemplify, param_name="Folder Name",
                                                   default_value="Junk Email", print_value=True)
    subject_filter = extract_action_parameter(siemplify=siemplify, param_name="Subject Filter", print_value=True)
    from_filter = extract_action_parameter(siemplify=siemplify, param_name="Sender Filter", print_value=True)
    recipient_filter = extract_action_parameter(siemplify=siemplify, param_name="Recipient Filter", print_value=True)
    mark_all_matching_emails = extract_action_parameter(siemplify=siemplify, param_name="Unmark All Matching Emails",
                                                        input_type=bool, print_value=True)
    all_mailboxes = extract_action_parameter(siemplify=siemplify, param_name="Perform action in all mailboxes",
                                             input_type=bool, print_value=True)
    batch_size = extract_action_parameter(siemplify=siemplify,
                                          param_name="How many mailboxes to process in a single batch",
                                          input_type=int, default_value=MAILBOX_DEFAULT_LIMIT)

    minutes_backwards = extract_action_parameter(siemplify=siemplify, param_name="Time Frame (minutes)", input_type=int,
                                                 print_value=True)

    message_ids = [message_id.strip() for message_id in message_ids_string.split(PARAMETERS_DEFAULT_DELIMITER)
                   if message_id.strip()] if message_ids_string else []
    mailboxes = [mailbox.strip() for mailbox in mailboxes_string.split(PARAMETERS_DEFAULT_DELIMITER)
                 if mailbox.strip()] if mailboxes_string else []
    folder_names = [folder_name.strip() for folder_name in folder_names_string.split(PARAMETERS_DEFAULT_DELIMITER)
                    if folder_name.strip()] if folder_names_string else []
    # Use pytz timezone object
    time_filter = utc_now().replace(tzinfo=pytz.utc) - timedelta(minutes=int(minutes_backwards)) \
        if minutes_backwards else None

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    try:
        # Create new exchange manager instance
        manager = init_manager(siemplify, INTEGRATION_NAME)

        # Check version support
        if not manager.is_supporting_version(EXCHANGE_2013):
            raise NotSupportedVersionException

        # Check if script timeout approaching
        if is_script_timeout(siemplify):
            additional_data = json.loads(siemplify.parameters["additional_data"])
            successful_messages = [manager.parser.get_message_data(message_json, False)
                                   for message_json in additional_data.get("successful_messages", [])]
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            json_result, output_message = prepare_results(successful_messages, failed_mailboxes)

            if json_result:
                siemplify.result.add_result_json(json_result)

            raise TimeoutException

        if is_first_run:
            not_processed_mailboxes = mailboxes if mailboxes else manager.get_searchable_mailboxes_addresses(all_mailboxes)
            siemplify.LOGGER.info(f"Found {len(not_processed_mailboxes)} searchable mailboxes.")
            successful_messages = []
            processed_mailboxes = []
            failed_mailboxes = []
        else:
            additional_data = json.loads(siemplify.parameters["additional_data"])
            successful_messages = [manager.parser.get_message_data(message_json, False)
                                   for message_json in additional_data.get("successful_messages", [])]
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])

        batch = not_processed_mailboxes[:batch_size]
        siemplify.LOGGER.info(f"Processing {len(batch)} mailboxes.")

        batch_successful_messages, batch_failed_mailboxes = not_junk_mail(
            logger=siemplify.LOGGER,
            manager=manager,
            move_items=move_items,
            message_ids=message_ids,
            mailboxes=batch,
            folder_names=folder_names,
            subject_filter=subject_filter,
            from_filter=from_filter,
            recipient_filter=recipient_filter,
            mark_all_matching_emails=mark_all_matching_emails,
            time_filter=time_filter
        )

        siemplify.LOGGER.info(f"Marked {len(batch_successful_messages)} messages as not junk from "
                              f"{len(batch) - len(batch_failed_mailboxes)} mailboxes (out of {len(batch)} mailboxes"
                              f" in current batch).")

        processed_mailboxes.extend(batch)
        not_processed_mailboxes = not_processed_mailboxes[batch_size:]
        failed_mailboxes.extend(batch_failed_mailboxes)
        successful_messages.extend(batch_successful_messages)

        if not not_processed_mailboxes:
            # Completed processing all mailboxes
            if not successful_messages:
                raise NotFoundEmailsException

            result_value = True
            status = EXECUTION_STATE_COMPLETED
            json_result, output_message = prepare_results(successful_messages, failed_mailboxes)

            if json_result:
                siemplify.result.add_result_json(json_result)
        else:
            # There are still mailboxes to process
            additional_data = {
                "successful_messages": [message.to_json() for message in successful_messages],
                "failed_mailboxes": failed_mailboxes,
                "not_processed_mailboxes": not_processed_mailboxes,
                "processed_mailboxes": processed_mailboxes
            }
            output_message = f"{len(successful_messages)} email(s) were unmarked as junk from " \
                             f"{len(processed_mailboxes)} mailboxes (out of " \
                             f"{len(processed_mailboxes) + len(not_processed_mailboxes)}). Continuing."

            status = EXECUTION_STATE_INPROGRESS
            result_value = json.dumps(additional_data)

    except TimeoutException:
        result_value = False
        status = EXECUTION_STATE_TIMEDOUT
    except NotSupportedVersionException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Failed to execute action - Action is fully supported only from Exchange Server version " \
                         f"2013 and above. Please make sure you have the appropriate version configured in Siemplify."
    except NotFoundEmailsException:
        result_value = False
        output_message = "No mails were found matching the search criteria!"
        status = EXECUTION_STATE_COMPLETED
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {UNBLOCK_SENDER_BY_MESSAGE_ID_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error performing \"{UNBLOCK_SENDER_BY_MESSAGE_ID_SCRIPT_NAME}\" action : {e}"
        additional_data_json = extract_action_parameter(siemplify=siemplify, param_name="additional_data",
                                                        default_value="{}")
        output_message, result_value, status = ExchangeCommon.prevent_async_action_fail_in_case_of_network_error(
            e,
            additional_data_json,
            MAX_RETRY,
            output_message,
            result_value,
            status
        )

    siemplify.LOGGER.info("----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


def is_script_timeout(siemplify):
    """
    Check if script timeout approaching
    :param siemplify: SiemplifyAction object.
    :return: {bool} True - if timeout approaching, False - otherwise.
    """
    return unix_now() + ITERATION_DURATION_BUFFER + ITERATIONS_INTERVAL >= siemplify.execution_deadline_unix_time_ms


def prepare_results(successful_messages, failed_mailboxes):
    """
    Prepare json result and output message
    :param successful_messages: The list of MessageData objects
    :param failed_mailboxes: The list of failed mailboxes
    :return: {tuple} json result and output message
    """
    output_message = ""

    if failed_mailboxes:
        output_message += f"Failed to access following mailboxes - " \
                          f"{PARAMETERS_DEFAULT_DELIMITER.join(failed_mailboxes)}\n"

    json_result = json.dumps([message.to_json() for message in successful_messages])
    output_message += f"\n{len(successful_messages)} mails were successfully unmarked as junk"
    return json_result, output_message


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
