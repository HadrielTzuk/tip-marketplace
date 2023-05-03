from ExchangeActions import extract_action_parameter, init_manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyUtils import output_handler, utc_now
from SiemplifyAction import SiemplifyAction
from constants import INTEGRATION_NAME, DELETE_MAIL_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER, MAILBOX_DEFAULT_LIMIT
from exceptions import NotFoundEmailsException
import pytz
import json
import sys
from ExchangeCommon import ExchangeCommon
from datetime import timedelta


# maximum retry count in case of network error
MAX_RETRY = 5


def delete_mail_from_mailboxes(em, logger, mailboxes, folders_names, message_ids, subject_filter, sender_filter,
                               recipient_filter, delete_all, time_filter):
    """
    Delete mail from given mailboxes
    :param em: {ExchangeManager} The exchange manager
    :param logger: {SiemplifyLogger} Logger
    :param mailboxes: {list} List of mailbox addresses to delete mail from
    :param folders_names: {list} List of folders names to search emails
    :param message_ids: {str} The message IDs to filter by
    :param subject_filter: {str} Filter by subject, default is None
    :param sender_filter: {str} Filter by sender, default is None
    :param recipient_filter: {str} Filter by recipient, default is None
    :param delete_all: {bool} Delete all suitable messages or only the first
    :param time_filter: {datetime} Filter by time
    :return: {tuple} List of MessageData objects and failed mailboxes
    """
    failed_mailboxes = []
    successful_messages = []

    for mailbox in mailboxes:
        try:
            logger.info(f"Deleting messages from mailbox {mailbox}")

            if message_ids:
                for message_id in message_ids:
                    try:
                        messages = em.delete_mail_from_mailbox(
                            folders_names=folders_names,
                            message_id=message_id,
                            delete_all_options=delete_all,
                            mailbox_address=mailbox,
                            time_filter=time_filter
                        )
                        successful_messages.extend(messages)

                    except Exception as e:
                        logger.error(f"Failed to delete messages from mailbox {mailbox}.")
                        logger.exception(e)
                        failed_mailboxes.append(mailbox)

            else:
                successful_messages.extend(em.delete_mail_from_mailbox(
                    folders_names=folders_names,
                    subject_filter=subject_filter,
                    sender_filter=sender_filter,
                    recipient_filter=recipient_filter,
                    delete_all_options=delete_all,
                    mailbox_address=mailbox,
                    time_filter=time_filter
                ))

        except Exception as e:
            logger.error(f"Failed to delete messages from mailbox {mailbox}.")
            logger.exception(e)
            failed_mailboxes.append(mailbox)

    return successful_messages, list(set(failed_mailboxes))


@output_handler
def main(is_first_run=True):
    siemplify = SiemplifyAction()
    siemplify.script_name = DELETE_MAIL_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    output_message = ''

    # Load action parameters
    folders_names_string = extract_action_parameter(siemplify=siemplify, param_name="Folder Name")
    message_ids_string = extract_action_parameter(siemplify=siemplify, param_name="Message IDs")
    subject_filter = extract_action_parameter(siemplify=siemplify, param_name="Subject Filter")
    sender_filter = extract_action_parameter(siemplify=siemplify, param_name="Sender Filter")
    recipient_filter = extract_action_parameter(siemplify=siemplify, param_name="Recipient Filter")
    delete_all = extract_action_parameter(siemplify=siemplify, param_name="Delete All Matching Emails", input_type=bool,
                                          default_value=False)
    mailboxes_string = extract_action_parameter(siemplify=siemplify, param_name="Mailboxes", default_value="")

    delete_from_all_mailboxes = extract_action_parameter(siemplify=siemplify, param_name="Delete from all mailboxes",
                                                         input_type=bool, default_value=False)
    batch_size = extract_action_parameter(siemplify=siemplify,
                                          param_name="How many mailboxes to process in a single batch",
                                          input_type=int, is_mandatory=False, default_value=MAILBOX_DEFAULT_LIMIT)
    minutes_backwards = extract_action_parameter(siemplify=siemplify, param_name="Time Frame (minutes)", input_type=int)

    message_ids = [m.strip() for m in message_ids_string.split(PARAMETERS_DEFAULT_DELIMITER)
                   if m and m.strip()] if message_ids_string else []

    folders_names = [folder.strip() for folder in folders_names_string.split(PARAMETERS_DEFAULT_DELIMITER)
                     if folder.strip()] if folders_names_string else ['Inbox']
    mailboxes = [mailbox.strip() for mailbox in mailboxes_string.split(PARAMETERS_DEFAULT_DELIMITER)
                 if mailbox.strip()] if mailboxes_string else []

    # Use pytz timezone object
    time_filter = utc_now().replace(tzinfo=pytz.utc) - timedelta(minutes=int(minutes_backwards)) \
        if minutes_backwards else None

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        em = init_manager(siemplify, INTEGRATION_NAME)

        if is_first_run:
            not_processed_mailboxes = mailboxes if mailboxes else em.get_searchable_mailboxes_addresses(delete_from_all_mailboxes)
            siemplify.LOGGER.info(f"Found {len(not_processed_mailboxes)} searchable mailboxes.")
            processed_mailboxes = []
            successful_messages_jsons = []
            failed_mailboxes = []

        else:
            additional_data = json.loads(siemplify.parameters['additional_data'])
            successful_messages_jsons = additional_data.get("successful_messages_jsons", [])
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])

        batch = not_processed_mailboxes[:batch_size]
        siemplify.LOGGER.info(f"Processing {len(batch)} mailboxes.")
        batch_successful_messages, batch_failed_mailboxes = delete_mail_from_mailboxes(em, siemplify.LOGGER, batch,
                                                                                       folders_names, message_ids,
                                                                                       subject_filter, sender_filter,
                                                                                       recipient_filter, delete_all,
                                                                                       time_filter)

        siemplify.LOGGER.info(
            f"Deleted {len(batch_successful_messages)} messages from {len(batch) - len(batch_failed_mailboxes)} mailboxes (out of {len(batch)} mailboxes in current batch).")

        processed_mailboxes.extend(batch)
        not_processed_mailboxes = not_processed_mailboxes[batch_size:]
        failed_mailboxes.extend(batch_failed_mailboxes)
        successful_messages_jsons.extend([message.to_json() for message in batch_successful_messages])

        if not not_processed_mailboxes:
            # Completed processing all mailboxes
            if not successful_messages_jsons:
                raise NotFoundEmailsException

            if failed_mailboxes:
                output_message += "Failed to access following mailboxes - {}\n" \
                    .format(PARAMETERS_DEFAULT_DELIMITER.join(failed_mailboxes))

            siemplify.result.add_result_json(successful_messages_jsons)
            output_message += "{} email(s) were deleted successfully".format(len(successful_messages_jsons))
            status = EXECUTION_STATE_COMPLETED
            result_value = True

        else:
            # There are still mailboxes to process
            additional_data = {
                "successful_messages_jsons": successful_messages_jsons,
                "failed_mailboxes": failed_mailboxes,
                "not_processed_mailboxes": not_processed_mailboxes,
                "processed_mailboxes": processed_mailboxes
            }
            output_message += f"{len(successful_messages_jsons)} email(s) were deleted from {len(processed_mailboxes)} mailboxes (out " \
                              f"of {len(processed_mailboxes) + len(not_processed_mailboxes)}). Continuing."
            status = EXECUTION_STATE_INPROGRESS
            result_value = json.dumps(additional_data)

    except NotFoundEmailsException:
        result_value = False
        output_message = "Failed to find emails for deletion!"
        status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(DELETE_MAIL_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Error deleting emails {}".format(e)
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
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
