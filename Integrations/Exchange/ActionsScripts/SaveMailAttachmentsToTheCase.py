from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ExchangeActions import extract_action_parameter, init_manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, SAVE_MAIL_ATTACHMENTS_TO_THE_CASE_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER
from exceptions import NotFoundAttachmentsException, NotFoundEmailsException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SAVE_MAIL_ATTACHMENTS_TO_THE_CASE_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    folders_string = extract_action_parameter(siemplify=siemplify, param_name='Folder Name', is_mandatory=True)
    message_id = extract_action_parameter(siemplify=siemplify, param_name='Message ID', is_mandatory=True)
    attachment_name = extract_action_parameter(siemplify=siemplify, param_name='Attachment To Save')

    folders_names = [f.strip() for f in folders_string.split(PARAMETERS_DEFAULT_DELIMITER) if
                     f.strip()] if folders_string else []

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    saved_attachments = []
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    output_message = ''

    try:
        em = init_manager(siemplify, INTEGRATION_NAME)
        em.enable_support_all_attachment_types()
        message = None

        for folder in folders_names:
            try:
                filtered_messages = em.get_messages_data(message_id=message_id, folder_name=folder).results
                if filtered_messages:
                    # since we are fetching by message_id we should get only first (and only?) one
                    message = filtered_messages[0]

            except Exception as e:
                siemplify.LOGGER.error('Failed to get email from folder={} with message_id={}'
                                       .format(folder, message_id))
                siemplify.LOGGER.exception(e)

        if not message:
            raise NotFoundEmailsException

        attachments = message.attachments_list

        # Filters attachments list by a specific attachment(s) name if filter value exist
        if attachment_name:
            attachments = {filename: content for filename, content in attachments.items() if
                           filename == attachment_name}

        if not attachments:
            raise NotFoundAttachmentsException

        try:
            for filename, content in attachments.items():
                siemplify.result.add_attachment(title=message_id,
                                                filename=filename,
                                                file_contents=content)
                saved_attachments.append(filename)

        except Exception as e:
            siemplify.LOGGER.exception(e)

        if saved_attachments:
            siemplify.result.add_result_json(message.to_json())
            output_message = 'Successfully saved the following attachments from the email {}: {}'\
                .format(message_id, PARAMETERS_DEFAULT_DELIMITER.join(saved_attachments))
            result_value = True

    except NotFoundEmailsException:
        output_message = 'No email was found'
    except NotFoundAttachmentsException:
        output_message = 'No attachments found in email {}'.format(message_id)
    except Exception as e:
        siemplify.LOGGER.error('General error performing action {}'
                               .format(SAVE_MAIL_ATTACHMENTS_TO_THE_CASE_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = 'Failed to save the email attachments to the case, the error is: {}'.format(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result Value: {}'.format(result_value))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
