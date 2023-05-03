import re
from ExchangeActions import extract_action_parameter, init_manager, is_rtl, add_rtl_html_divs_to_body
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import INTEGRATION_NAME, SEND_VOTE_MAIL_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER, VOTING_OPTIONS, \
    EMAIL_REGEX
from exceptions import IncompleteInfoException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEND_VOTE_MAIL_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init ----------------")

    # Action parameters
    subject = extract_action_parameter(siemplify=siemplify, param_name="Subject", is_mandatory=True, print_value=True)
    recipients_string = extract_action_parameter(siemplify=siemplify, param_name="Send To", is_mandatory=True,
                                                 print_value=True)
    cc_recipients = extract_action_parameter(siemplify=siemplify, param_name="CC", print_value=True)
    bcc_recipients = extract_action_parameter(siemplify=siemplify, param_name="BCC", print_value=True)
    attachments_paths_string = extract_action_parameter(siemplify=siemplify, param_name="Attachments Paths",
                                                        print_value=True)
    content = extract_action_parameter(siemplify=siemplify, param_name="Question or Decision Description",
                                       is_mandatory=True, print_value=True)
    voting_options = extract_action_parameter(siemplify=siemplify, param_name="Structure of voting options",
                                              is_mandatory=True, print_value=True)

    recipients = [recipient.strip() for recipient in recipients_string.split(PARAMETERS_DEFAULT_DELIMITER)
                  if recipient.strip()] if recipients_string else []

    attachments_paths = [path.strip() for path in attachments_paths_string.split(PARAMETERS_DEFAULT_DELIMITER)
                         if path.strip()] if attachments_paths_string else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    output_message = "Vote Mail was sent successfully"
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        valid_recipients = [recipient for recipient in recipients if re.search(EMAIL_REGEX, recipient)]
        invalid_recipients = list(set(recipients) - set(valid_recipients))

        if not valid_recipients:
            raise IncompleteInfoException

        # Create new exchange manager instance
        manager = init_manager(siemplify, INTEGRATION_NAME)
        generate_mail_id = manager.is_writable_mail_id_supported()

        # If the content is rtl edit the html message
        if is_rtl(content):
            content = add_rtl_html_divs_to_body(content)

        result = manager.send_mail_html_embedded_photos(PARAMETERS_DEFAULT_DELIMITER.join(valid_recipients),
                                                        subject, content, attachments_paths, cc_recipients,
                                                        bcc_recipients, generate_mail_id,
                                                        VOTING_OPTIONS.get(voting_options))

        if result:
            siemplify.result.add_result_json(result.to_json())
        else:
            output_message = "Vote Mail was sent successfully. Json result cannot be generated, since this is only " \
                             "supported in Exchange Server Version 2013 and above"

        if invalid_recipients:
            output_message += f"\nCould not send vote mail for the following mailboxes: " \
                              f"{PARAMETERS_DEFAULT_DELIMITER.join(invalid_recipients)}"

    except IncompleteInfoException:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = "Could not send vote mail to any of the provided mailboxes. Please check the action " \
                         "parameters and try again"
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {SEND_VOTE_MAIL_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Failed to send mail with vote. Error is: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
