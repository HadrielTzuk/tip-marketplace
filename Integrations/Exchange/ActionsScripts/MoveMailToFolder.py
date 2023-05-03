from SiemplifyUtils import output_handler, utc_now
from SiemplifyAction import SiemplifyAction
from ExchangeActions import extract_action_parameter, init_manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from constants import INTEGRATION_NAME, MOVE_MAIL_TO_FOLDER_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER, \
    MAILBOX_DEFAULT_LIMIT
from exceptions import NotFoundEmailsException
import pytz
import json
import sys
from ExchangeCommon import ExchangeCommon
from datetime import timedelta

# maximum retry count in case of network error
MAX_RETRY = 5
LIMIT_JSON_RESULT_DEFAULT_VALUE = True
DISABLE_JSON_RESULT_DEFAULT_VALUE = False


def move_mail(em, logger, mailboxes, dst_folder_name, src_folder_name, subject_filter, message_ids, only_unread,
              time_filter):
    """
    Move mail
    :param em: {ExchangeManager} The exchange manager
    :param logger: {SiemplifyLogger} Logger
    :param mailboxes: {list} List of mailbox addresses to move the mail from
    :param dst_folder_name: {str} Destination folder name, where target emails would be moved
    :param src_folder_name: {str} Source folder name, from which found emails would be moved to the target folder
    :param subject_filter: {str} Subject to filter emails by
    :param message_ids: {str} The ids of the messages to move
    :param only_unread: {bool} True if only unread, False otherwise.
    :param time_filter: {datetime} Filter by time
    :return: {tuple} List of MessageData objects and failed mailboxes
    """
    failed_mailboxes = []
    successful_messages = []

    for mailbox in mailboxes:
        try:
            logger.info(f"Moving messages from mailbox {mailbox}")

            if message_ids:
                for message_id in message_ids:
                    try:
                        messages = em.move_mail_from_mailbox(
                            dst_folder_name=dst_folder_name,
                            src_folder_name=src_folder_name,
                            message_id=message_id,
                            only_unread=only_unread,
                            subject_filter=subject_filter,
                            mailbox_address=mailbox,
                            time_filter=time_filter
                        )
                        successful_messages.extend(messages)

                    except Exception as e:
                        logger.error(f"Failed to move messages from mailbox {mailbox}.")
                        logger.exception(e)
                        failed_mailboxes.append(mailbox)

            else:
                successful_messages.extend(em.move_mail_from_mailbox(
                    dst_folder_name=dst_folder_name,
                    src_folder_name=src_folder_name,
                    only_unread=only_unread,
                    subject_filter=subject_filter,
                    mailbox_address=mailbox,
                    time_filter=time_filter
                ))

        except Exception as e:
            logger.error(f"Failed to move messages from mailbox {mailbox}.")
            logger.exception(e)
            failed_mailboxes.append(mailbox)

    return successful_messages, list(set(failed_mailboxes))


@output_handler
def main(is_first_run=True):
    siemplify = SiemplifyAction()
    siemplify.script_name = MOVE_MAIL_TO_FOLDER_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    src_folder_name = extract_action_parameter(siemplify=siemplify, param_name="Source Folder Name", is_mandatory=True)
    dst_folder_name = extract_action_parameter(siemplify=siemplify, param_name="Destination Folder Name",
                                               is_mandatory=True)
    message_ids_string = extract_action_parameter(siemplify=siemplify, param_name="Message IDs")
    subject_filter = extract_action_parameter(siemplify=siemplify, param_name="Subject Filter")
    only_unread = extract_action_parameter(siemplify=siemplify, param_name="Only Unread", input_type=bool,
                                           default_value=False)
    move_in_all_mailboxes = extract_action_parameter(siemplify=siemplify, param_name="Move in all mailboxes",
                                                     input_type=bool, default_value=False)
    minutes_backwards = extract_action_parameter(siemplify=siemplify, param_name="Time Frame (minutes)", input_type=int)

    message_ids = [mid.strip() for mid in message_ids_string.split(PARAMETERS_DEFAULT_DELIMITER)
                   if mid and mid.strip()] if message_ids_string else []
    batch_size = extract_action_parameter(siemplify=siemplify,
                                          param_name="How many mailboxes to process in a single batch",
                                          input_type=int, is_mandatory=False, default_value=MAILBOX_DEFAULT_LIMIT)
    limit_json_result = extract_action_parameter(siemplify=siemplify, input_type=bool,
                                                 param_name="Limit the Amount of Information Returned in the JSON "
                                                            "Result",
                                                 default_value=LIMIT_JSON_RESULT_DEFAULT_VALUE)

    disable_json_result = extract_action_parameter(siemplify=siemplify, input_type=bool,
                                                   param_name="Disable the Action JSON Result",
                                                   default_value=DISABLE_JSON_RESULT_DEFAULT_VALUE)
    # Use pytz timezone object
    time_filter = utc_now().replace(tzinfo=pytz.utc) - timedelta(minutes=int(minutes_backwards)) \
        if minutes_backwards else None

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        # Create new exchange manager instance
        em = init_manager(siemplify, INTEGRATION_NAME)
        if is_first_run:
            not_processed_mailboxes = em.get_searchable_mailboxes_addresses(move_in_all_mailboxes)
            siemplify.LOGGER.info(f"Found {len(not_processed_mailboxes)} searchable mailboxes.")
            processed_mailboxes = []
            successful_messages = []
            failed_mailboxes = []
        else:
            additional_data = json.loads(siemplify.parameters['additional_data'])
            successful_messages = [em.parser.get_message_data(message_json, False) for message_json
                                   in additional_data.get("successful_messages", [])]
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])

        batch = not_processed_mailboxes[:batch_size]
        siemplify.LOGGER.info(f"Processing {len(batch)} mailboxes.")
        batch_successful_messages, batch_failed_mailboxes = move_mail(em=em, logger=siemplify.LOGGER, mailboxes=batch,
                                                                      dst_folder_name=dst_folder_name,
                                                                      subject_filter=subject_filter,
                                                                      src_folder_name=src_folder_name,
                                                                      message_ids=message_ids,
                                                                      only_unread=only_unread,
                                                                      time_filter=time_filter)

        siemplify.LOGGER.info(
            f"Moved {len(batch_successful_messages)} messages from {len(batch) - len(batch_failed_mailboxes)} mailboxes (out of {len(batch)} mailboxes in current batch).")

        processed_mailboxes.extend(batch)
        not_processed_mailboxes = not_processed_mailboxes[batch_size:]
        failed_mailboxes.extend(batch_failed_mailboxes)
        successful_messages.extend(batch_successful_messages)

        if not not_processed_mailboxes:
            # Completed processing all mailboxes
            if not successful_messages:
                raise NotFoundEmailsException

            output_message = ''
            if failed_mailboxes:
                output_message += "Failed to access following mailboxes - {}\n" \
                    .format(PARAMETERS_DEFAULT_DELIMITER.join(failed_mailboxes))

            status = EXECUTION_STATE_COMPLETED
            result_value = True

            if not limit_json_result:
                json_result = json.dumps([message.to_json() for message in successful_messages])
            else:
                json_result = json.dumps([message.to_shorthand_json() for message in successful_messages])
            if not disable_json_result:
                siemplify.result.add_result_json(json_result)
            output_message += "\n\n{} mails were successfully moved from {} to {}" \
                .format(len(successful_messages), src_folder_name, dst_folder_name)

        else:
            # There are still mailboxes to process
            additional_data = {
                "successful_messages": [message.to_json() for message in successful_messages],
                "failed_mailboxes": failed_mailboxes,
                "not_processed_mailboxes": not_processed_mailboxes,
                "processed_mailboxes": processed_mailboxes
            }
            output_message = f"{len(successful_messages)} email(s) were found in {len(processed_mailboxes)} mailboxes (out " \
                             f"of {len(processed_mailboxes) + len(not_processed_mailboxes)}). Continuing."
            status = EXECUTION_STATE_INPROGRESS
            result_value = json.dumps(additional_data)

    except NotFoundEmailsException:
        result_value = False
        output_message = "No mails were found matching the search criteria!"
        status = EXECUTION_STATE_COMPLETED
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(MOVE_MAIL_TO_FOLDER_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Error search emails: {}".format(e)
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


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
