from ExchangeActions import extract_action_parameter, init_manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from constants import INTEGRATION_NAME, SEND_MAIL_HTML_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEND_MAIL_HTML_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    output_message = "Mail sent successfully"
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    send_to = extract_action_parameter(siemplify=siemplify, param_name="Send to", is_mandatory=True)
    subject = extract_action_parameter(siemplify=siemplify, param_name="Subject", is_mandatory=True)
    content = extract_action_parameter(siemplify=siemplify, param_name="Mail content", is_mandatory=True)
    cc = extract_action_parameter(siemplify=siemplify, param_name="CC")
    bcc = extract_action_parameter(siemplify=siemplify, param_name="BCC")
    attachment_paths_string = extract_action_parameter(siemplify=siemplify, param_name="Attachments Paths")

    attachment_paths = [a.strip() for a in attachment_paths_string.split(PARAMETERS_DEFAULT_DELIMITER) if a.strip()] \
        if attachment_paths_string else []

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        # Create new exchange manager instance
        em = init_manager(siemplify, INTEGRATION_NAME)
        generate_mail_id = em.is_writable_mail_id_supported()

        em.send_mail_html_embedded_photos(to_addresses=send_to,
                                          subject=subject,
                                          html_body=content,
                                          attachments_paths=attachment_paths,
                                          cc=cc,
                                          bcc=bcc,
                                          generate_mail_id=generate_mail_id)
    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SEND_MAIL_HTML_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "An error occurred while running action: {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)

        
if __name__ == "__main__":
    main()
