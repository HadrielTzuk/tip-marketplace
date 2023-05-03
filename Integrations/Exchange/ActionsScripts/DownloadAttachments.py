import os
import sys
import json
from ExchangeActions import extract_action_parameter, init_manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from constants import INTEGRATION_NAME, DOWNLOAD_ATTACHMENTS_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER, NEW_LINE, \
    MAILBOX_DEFAULT_LIMIT
from exceptions import NotFoundEmailsException, NotFoundException
from ExchangeCommon import ExchangeCommon


# maximum retry count in case of network error
MAX_RETRY = 5


def download_attachments_from_mailboxes(em, logger, mailboxes, folders_names, message_ids, from_filter, subject_filter,
                                        only_unread, local_path, download_from_eml, unique_path):
    """
    Search mails in given mailboxes and download attachments
    :param em: {ExchangeManager} The exchange manager
    :param logger: {SiemplifyLogger} Logger
    :param mailboxes: {list} List of mailbox addresses to search mails
    :param folders_names: {list} List of folders names to search emails
    :param message_ids: {str} The message IDs to filter by
    :param subject_filter: {str} Filter by subject
    :param from_filter: {str} Filter by sender
    :param only_unread: {bool} Fetch only unread emails
    :param local_path: {bool} Path for downloading emails attachments
    :param download_from_eml: {bool} Specifies if download attachments also from attached EML files
    :param unique_path: {str} Specifies if path for downloading emails attachments should be unique
    :return: {tuple} List of AttachmentData objects and failed mailboxes
    """
    failed_mailboxes = []
    successful_attachments = []
    emails = []

    for mailbox in mailboxes:
        logger.info(f"Getting messages from mailbox {mailbox}")

        if message_ids:
            for message_id in message_ids:
                try:
                    emails.extend(em.search_mail_in_mailbox(mailbox_address=mailbox,
                                                            folders_names=folders_names,
                                                            message_id=message_id,
                                                            only_unread=only_unread,
                                                            siemplify_result=False))
                except Exception as e:
                    logger.error(f"Failed to search messages in mailbox {mailbox}.")
                    logger.exception(e)
                    failed_mailboxes.append(mailbox)
        else:
            try:
                emails.extend(em.search_mail_in_mailbox(mailbox_address=mailbox,
                                                        folders_names=folders_names,
                                                        subject_filter=subject_filter,
                                                        from_filter=from_filter,
                                                        only_unread=only_unread,
                                                        siemplify_result=False))
            except Exception as e:
                logger.error(f"Failed to search messages in mailbox {mailbox}.")
                logger.exception(e)
                failed_mailboxes.append(mailbox)

    logger.info(f"Found {len(emails)} emails in folders={PARAMETERS_DEFAULT_DELIMITER.join(folders_names)} with "
                f"message_ids={PARAMETERS_DEFAULT_DELIMITER.join(message_ids)}, subject_filter={subject_filter}, "
                f"from_filter={from_filter}, only_unread={only_unread}")

    for email in emails:
        try:
            # Download and save the attachments to the given path
            successful_attachments.extend(em.save_attachments_to_local_path(email, local_path, download_from_eml,
                                                                            unique_path))
        except Exception as e:
            logger.error("Unable to download attachment for {}: {}".format(email.message_id, e))
            logger.exception(e)

    return successful_attachments, list(set(failed_mailboxes))


@output_handler
def main(is_first_run=True):
    siemplify = SiemplifyAction()
    siemplify.script_name = DOWNLOAD_ATTACHMENTS_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    folders_names_string = extract_action_parameter(siemplify=siemplify, param_name="Folder Name", is_mandatory=True,
                                                    default_value="Inbox")
    local_path = extract_action_parameter(siemplify=siemplify, param_name="Download Path", is_mandatory=True)
    message_ids_string = extract_action_parameter(siemplify=siemplify, param_name="Message IDs")

    subject_filter = extract_action_parameter(siemplify=siemplify, param_name="Subject Filter")
    sender_filter = extract_action_parameter(siemplify=siemplify, param_name="Sender Filter")
    only_unread = extract_action_parameter(siemplify=siemplify, param_name="Only Unread", input_type=bool,
                                           default_value=False)
    download_from_eml = extract_action_parameter(siemplify=siemplify, param_name="Download Attachments from EML",
                                                 input_type=bool, default_value=False)
    unique_path = extract_action_parameter(siemplify=siemplify, param_name="Download Attachments to unique path?",
                                           input_type=bool)
    search_in_all_mailboxes = extract_action_parameter(siemplify=siemplify, param_name="Search in all mailboxes",
                                                       input_type=bool)
    batch_size = extract_action_parameter(siemplify=siemplify,
                                          param_name="How many mailboxes to process in a single batch",
                                          input_type=int, default_value=MAILBOX_DEFAULT_LIMIT)

    mailboxes_string = extract_action_parameter(siemplify=siemplify, param_name="Mailboxes")

    message_ids = [m.strip() for m in message_ids_string.split(PARAMETERS_DEFAULT_DELIMITER)
                   if m and m.strip()] if message_ids_string else []

    folders_names = [folder.strip() for folder in folders_names_string.split(PARAMETERS_DEFAULT_DELIMITER)
                     if folder.strip()] if folders_names_string else ['Inbox']

    mailboxes = [mailbox.strip() for mailbox in mailboxes_string.split(PARAMETERS_DEFAULT_DELIMITER)
                 if mailbox.strip()] if mailboxes_string else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        # Create new exchange manager instance
        em = init_manager(siemplify, INTEGRATION_NAME)

        # Create the local path dir if it doesn't exist
        if not os.path.exists(local_path):
            os.makedirs(local_path)
            siemplify.LOGGER.info("Created new folder for downloading emails attachments: {}".format(local_path))

        if is_first_run:
            not_processed_mailboxes = get_available_mailboxes(em, mailboxes, search_in_all_mailboxes)
            siemplify.LOGGER.info(f"Found {len(not_processed_mailboxes)} searchable mailboxes.")
            processed_mailboxes = []
            successful_attachments = []
            failed_mailboxes = []
        else:
            additional_data = json.loads(siemplify.parameters['additional_data'])
            successful_attachments = [em.parser.get_attachment_data(item.get("attachment_name"), item.get("downloaded_path"))
                                      for item in additional_data.get("successful_attachments", [])]
            failed_mailboxes = additional_data.get("failed_mailboxes", [])
            processed_mailboxes = additional_data.get("processed_mailboxes", [])
            not_processed_mailboxes = additional_data.get("not_processed_mailboxes", [])

        batch = not_processed_mailboxes[:batch_size]
        siemplify.LOGGER.info(f"Processing {len(batch)} mailboxes.")

        batch_successful_attachments, batch_failed_mailboxes = download_attachments_from_mailboxes(
            em=em,
            logger=siemplify.LOGGER,
            mailboxes=batch,
            folders_names=folders_names,
            message_ids=message_ids,
            from_filter=sender_filter,
            subject_filter=subject_filter,
            only_unread=only_unread,
            local_path=local_path,
            download_from_eml=download_from_eml,
            unique_path=unique_path)

        siemplify.LOGGER.info(f"Found {len(batch_successful_attachments)} attachments from "
                              f"{len(batch) - len(batch_failed_mailboxes)} mailboxes (out of {len(batch)} mailboxes "
                              f"in current batch).")

        processed_mailboxes.extend(batch)
        not_processed_mailboxes = not_processed_mailboxes[batch_size:]
        failed_mailboxes.extend(batch_failed_mailboxes)
        successful_attachments.extend(batch_successful_attachments)

        if not not_processed_mailboxes:
            # Completed processing all mailboxes
            if not successful_attachments:
                raise NotFoundEmailsException

            output_message = ""
            if failed_mailboxes:
                output_message += "Failed to access following mailboxes - {}\n" \
                    .format(PARAMETERS_DEFAULT_DELIMITER.join(failed_mailboxes))

            files_paths = [successful_attachment.downloaded_path for successful_attachment in successful_attachments]
            result_value = PARAMETERS_DEFAULT_DELIMITER.join(files_paths)
            siemplify.result.add_result_json([data.to_json() for data in successful_attachments])
            status = EXECUTION_STATE_COMPLETED
            output_message += "Downloaded {} attachments. \n\nFiles:\n{}".format(len(files_paths),
                                                                                 NEW_LINE.join(files_paths))

        else:
            # There are still mailboxes to process
            additional_data = {
                "successful_attachments": [successful_attachment.to_json() for successful_attachment in successful_attachments],
                "failed_mailboxes": failed_mailboxes,
                "not_processed_mailboxes": not_processed_mailboxes,
                "processed_mailboxes": processed_mailboxes
            }
            output_message = f"{len(successful_attachments)} attachment(s) were found in {len(processed_mailboxes)} " \
                             f"mailboxes (out of {len(processed_mailboxes) + len(not_processed_mailboxes)}). Continuing."
            status = EXECUTION_STATE_INPROGRESS
            result_value = json.dumps(additional_data)

    except NotFoundException as e:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{DOWNLOAD_ATTACHMENTS_SCRIPT_NAME}\". Reason: the following " \
                         f"mailboxes were not found: {e}. Please check the spelling."
    except NotFoundEmailsException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "No emails found"
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(DOWNLOAD_ATTACHMENTS_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Failed to download email attachments, the error is: {}".format(e)
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

    if mailboxes:
        not_found_mailboxes = [mailbox for mailbox in mailboxes if mailbox not in available_mailboxes]

        if not_found_mailboxes:
            raise NotFoundException(PARAMETERS_DEFAULT_DELIMITER.join(not_found_mailboxes))

    return mailboxes if mailboxes else available_mailboxes


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
