from ExchangeActions import extract_action_parameter, init_manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyUtils import output_handler, utc_now
from SiemplifyAction import SiemplifyAction
import json
import sys
from constants import INTEGRATION_NAME, SEARCH_MAILS_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER, MAILBOX_DEFAULT_LIMIT
from TIPCommon import construct_csv, dict_to_flat
from exceptions import NotFoundEmailsException, NotFoundException
from ExchangeCommon import ExchangeCommon
from ExchangeUtilsManager import get_time_filters


# maximum retry count in case of network error
MAX_RETRY = 5


def search_mail_in_mailboxes(em, logger, mailboxes, folders_names, message_ids, subject_filter, start_time_filter,
                             end_time_filter, recipient_filter, from_filter, body_regex_filter, only_unread, limit):
    """
    Search mail in given mailboxes
    :param em: {ExchangeManager} The exchange manager
    :param logger: {SiemplifyLogger} Logger
    :param mailboxes: {list} List of mailbox addresses to search mail
    :param folders_names: {list} List of folders names to search emails
    :param message_ids: {str} The message IDs to filter by
    :param subject_filter: {str} Filter by subject
    :param start_time_filter: {datetime} Filter by start time
    :param end_time_filter: {datetime} Filter by end time
    :param recipient_filter: {str} Filter by recipient
    :param from_filter: {str} Filter by sender
    :param body_regex_filter: {str} Filter by body in regex format
    :param only_unread: {bool} Fetch only unread emails
    :param limit: {int} Max number of emails to return.
    :return: {tuple} List of MessageData objects and failed mailboxes
    """
    failed_mailboxes = []
    successful_messages = []

    for mailbox in mailboxes:
        try:
            logger.info(f"Searching messages in mailbox {mailbox}")

            if message_ids:
                for message_id in message_ids:
                    try:
                        messages = em.search_mail_in_mailbox(
                            mailbox_address=mailbox,
                            start_time_filter=start_time_filter,
                            end_time_filter=end_time_filter,
                            only_unread=only_unread,
                            folders_names=folders_names,
                            message_id=message_id,
                            limit=limit
                        )
                        successful_messages.extend(messages)

                    except Exception as e:
                        logger.error(f"Failed to search messages in mailbox {mailbox}.")
                        logger.exception(e)
                        failed_mailboxes.append(mailbox)
            else:
                successful_messages.extend(em.search_mail_in_mailbox(
                    mailbox_address=mailbox,
                    subject_filter=subject_filter,
                    start_time_filter=start_time_filter,
                    end_time_filter=end_time_filter,
                    recipient_filter=recipient_filter,
                    only_unread=only_unread,
                    from_filter=from_filter,
                    body_regex_filter=body_regex_filter,
                    folders_names=folders_names,
                    limit=limit
                ))

        except Exception as e:
            logger.error(f"Failed to search messages in mailbox {mailbox}.")
            logger.exception(e)
            failed_mailboxes.append(mailbox)

    return successful_messages, list(set(failed_mailboxes))


@output_handler
def main(is_first_run=True):
    siemplify = SiemplifyAction()
    siemplify.script_name = SEARCH_MAILS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    subject_filter = extract_action_parameter(siemplify=siemplify, param_name="Subject Filter")
    from_filter = extract_action_parameter(siemplify=siemplify, param_name="Sender Filter")
    recipient_filter = extract_action_parameter(siemplify=siemplify, param_name="Recipient Filter")
    minutes_backwards = extract_action_parameter(siemplify=siemplify, param_name="Time Frame (minutes)")
    only_unread = extract_action_parameter(siemplify=siemplify, param_name="Only Unread", input_type=bool,
                                           default_value=False)
    max_emails_to_return = extract_action_parameter(siemplify=siemplify, param_name="Max Emails To Return",
                                                    input_type=int)
    search_in_all_mailboxes = extract_action_parameter(siemplify=siemplify, param_name="Search in all mailboxes",
                                                       input_type=bool)
    folders_names_string = extract_action_parameter(siemplify=siemplify, param_name="Folder Name",
                                                    default_value="Inbox")
    message_ids_string = extract_action_parameter(siemplify=siemplify, param_name="Message IDs")

    folders_names = [folder.strip() for folder in folders_names_string.split(PARAMETERS_DEFAULT_DELIMITER)
                     if folder.strip()] if folders_names_string else ['Inbox']

    message_ids = [message_id.strip() for message_id in message_ids_string.split(PARAMETERS_DEFAULT_DELIMITER)
                   if message_id and message_id.strip()] if message_ids_string else []

    batch_size = extract_action_parameter(siemplify=siemplify,
                                          param_name="How many mailboxes to process in a single batch",
                                          input_type=int, is_mandatory=False, default_value=MAILBOX_DEFAULT_LIMIT)
    mailboxes_string = extract_action_parameter(siemplify=siemplify, param_name="Mailboxes")
    start_time = extract_action_parameter(siemplify=siemplify, param_name="Start Time")
    end_time = extract_action_parameter(siemplify=siemplify, param_name="End Time")
    body_regex_filter = extract_action_parameter(siemplify=siemplify, param_name="Body Regex Filter")

    mailboxes = [mailbox.strip() for mailbox in mailboxes_string.split(PARAMETERS_DEFAULT_DELIMITER)
                 if mailbox.strip()] if mailboxes_string else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        start_time, end_time = get_time_filters(start_time, end_time, minutes_backwards)

        # Create new exchange manager instance
        em = init_manager(siemplify, INTEGRATION_NAME)
        em.enable_support_all_attachment_types()

        if is_first_run:
            not_processed_mailboxes, non_valid_mailboxes = get_available_mailboxes(em, mailboxes, search_in_all_mailboxes)
            siemplify.LOGGER.info(f"Found {len(not_processed_mailboxes)} searchable mailboxes.")
            processed_mailboxes = []
            successful_messages = []
            failed_mailboxes = []
        else:
            additional_data = json.loads(siemplify.parameters['additional_data'])
            successful_messages = [em.parser.get_message_data(message_json, False) for message_json
                                   in additional_data.get("successful_messages", [])]
            failed_mailboxes = [em.parser.get_message_data(message_json, False) for message_json
                                in additional_data.get("failed_mailboxes", [])]
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])
            non_valid_mailboxes = additional_data.get("non_valid_mailboxes", [])

        batch = not_processed_mailboxes[:batch_size]
        siemplify.LOGGER.info(f"Processing {len(batch)} mailboxes.")
        batch_successful_messages, batch_failed_mailboxes = search_mail_in_mailboxes(em=em, logger=siemplify.LOGGER,
                                                                                     mailboxes=batch,
                                                                                     folders_names=folders_names,
                                                                                     message_ids=message_ids,
                                                                                     start_time_filter=start_time,
                                                                                     end_time_filter=end_time,
                                                                                     from_filter=from_filter,
                                                                                     subject_filter=subject_filter,
                                                                                     only_unread=only_unread,
                                                                                     recipient_filter=recipient_filter,
                                                                                     body_regex_filter=body_regex_filter,
                                                                                     limit=max_emails_to_return)
        siemplify.LOGGER.info(
            f"Found {len(batch_successful_messages)} messages from {len(batch) - len(batch_failed_mailboxes)} mailboxes (out of {len(batch)} mailboxes in current batch).")

        processed_mailboxes.extend(batch)
        not_processed_mailboxes = not_processed_mailboxes[batch_size:]
        failed_mailboxes.extend(batch_failed_mailboxes)
        successful_messages.extend(batch_successful_messages)

        if not not_processed_mailboxes:
            # Completed processing all mailboxes
            if not successful_messages:
                raise NotFoundEmailsException

            output_message = ''
            if non_valid_mailboxes:
                output_message += "The following mailboxes were not found:\n{}\n\n"\
                    .format("\n".join(non_valid_mailbox for non_valid_mailbox in non_valid_mailboxes))
            if failed_mailboxes:
                output_message += "Failed to access following mailboxes - {}\n\n" \
                    .format(PARAMETERS_DEFAULT_DELIMITER.join(failed_mailboxes))

            output_message += "Search found {} emails based on the provided search criteria".format(
                len(successful_messages))
            siemplify.result.add_data_table("Matching Mails",
                                            construct_csv([message.to_table() for message in successful_messages]))
            result_value = json.dumps([message.to_json() for message in successful_messages])
            siemplify.result.add_result_json(result_value)
            status = EXECUTION_STATE_COMPLETED

        else:
            # There are still mailboxes to process
            additional_data = {
                "successful_messages": [message.to_json() for message in successful_messages],
                "failed_mailboxes": [message.to_json() for message in failed_mailboxes],
                "not_processed_mailboxes": not_processed_mailboxes,
                "processed_mailboxes": processed_mailboxes,
                "non_valid_mailboxes": non_valid_mailboxes
            }
            output_message = f"{len(successful_messages)} email(s) were found in {len(processed_mailboxes)} mailboxes (out " \
                             f"of {len(processed_mailboxes) + len(not_processed_mailboxes)}). Continuing."
            status = EXECUTION_STATE_INPROGRESS
            result_value = json.dumps(additional_data)

    except NotFoundException as e:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{SEARCH_MAILS_SCRIPT_NAME}\". Reason: the following mailboxes " \
                         f"were not found: \n{e}\nPlease check the spelling."
    except NotFoundEmailsException:
        result_value = json.dumps([])
        siemplify.result.add_result_json(result_value)
        output_message = "Search didn't find any matching emails"
        status = EXECUTION_STATE_COMPLETED
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SEARCH_MAILS_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Search didn't completed successfully due to error: {}".format(e)
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


def get_available_mailboxes(manager, mailboxes=None, search_in_all_mailboxes=None):
    """
    Get available mailboxes
    :param manager: {ExchangeManager} ExchangeManager instance
    :param mailboxes: {list} List of mailboxes that need to be searched
    :param search_in_all_mailboxes: {bool} Specifies if all mailboxes should be searched
    :return: {list} The list of available mailboxes
    """
    all_mailboxes = search_in_all_mailboxes or bool(mailboxes)
    available_mailboxes = manager.get_searchable_mailboxes_addresses(all_mailboxes)

    not_found_mailboxes = []
    valid_mailboxes = []

    if mailboxes:
        not_found_mailboxes.extend(mailbox for mailbox in mailboxes if mailbox not in available_mailboxes)
        valid_mailboxes.extend(mailbox for mailbox in mailboxes if mailbox in available_mailboxes)

    if not_found_mailboxes and not valid_mailboxes:
        raise NotFoundException("\n".join(not_found_mailboxes))

    return (valid_mailboxes, not_found_mailboxes) if mailboxes else (available_mailboxes, [])


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
