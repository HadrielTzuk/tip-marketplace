from ExchangeActions import extract_action_parameter, init_manager, is_rtl, add_rtl_html_divs_to_body
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from constants import INTEGRATION_NAME, SEND_MAIL_SCRIPT_NAME, PARAMETERS_DEFAULT_DELIMITER


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEND_MAIL_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    status = EXECUTION_STATE_COMPLETED
    output_message = "Mail sent successfully."
    result_value = True

    send_to = extract_action_parameter(siemplify=siemplify, param_name="Send to", is_mandatory=True)
    cc = extract_action_parameter(siemplify=siemplify, param_name="CC")
    bcc = extract_action_parameter(siemplify=siemplify, param_name="BCC")
    subject = extract_action_parameter(siemplify=siemplify, param_name="Subject", is_mandatory=True)
    content = extract_action_parameter(siemplify=siemplify, param_name="Mail content", is_mandatory=True)
    attachment_paths_string = extract_action_parameter(siemplify=siemplify, param_name="Attachments Paths")
    reply_to_recipients_string = extract_action_parameter(siemplify=siemplify, param_name="Reply-To Recipients")

    attachment_paths = [a.strip() for a in attachment_paths_string.split(PARAMETERS_DEFAULT_DELIMITER)
                        if a.strip()] if attachment_paths_string else []

    reply_to_recipients = [item.strip() for item in reply_to_recipients_string.split(PARAMETERS_DEFAULT_DELIMITER)
                           if item.strip()] if reply_to_recipients_string else []

    base64_certificate = extract_action_parameter(siemplify=siemplify, param_name="Base64 Encoded Certificate")
    base64_private_key = extract_action_parameter(siemplify=siemplify, param_name="Base64 Encoded Signature")

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        # Create new exchange manager instance
        em = init_manager(siemplify, INTEGRATION_NAME)
        generate_mail_id = em.is_writable_mail_id_supported()

        # If the body is rtl edit the html message
        if is_rtl(content):
            content = add_rtl_html_divs_to_body(content)

        if base64_private_key and base64_certificate:
            result = em.send_signed_message(
                to_addresses=send_to,
                subject=subject,
                html_body=content,
                attachments_paths=attachment_paths,
                cc=cc,
                bcc=bcc,
                generate_mail_id=generate_mail_id,
                reply_to_recipients=reply_to_recipients,
                base64_certificate=base64_certificate,
                base64_private_key=base64_private_key
            )
        elif base64_certificate:
            result = em.send_encoded_mail(
                to_addresses=send_to,
                subject=subject,
                html_body=content,
                attachments_paths=attachment_paths,
                cc=cc,
                bcc=bcc,
                generate_mail_id=generate_mail_id,
                reply_to_recipients=reply_to_recipients,
                base64_certificate=base64_certificate
            )
        else:
            result = em.send_mail_html_embedded_photos(
                to_addresses=send_to,
                subject=subject,
                html_body=content,
                attachments_paths=attachment_paths,
                cc=cc,
                bcc=bcc,
                generate_mail_id=generate_mail_id,
                reply_to_recipients=reply_to_recipients
            )

        if result:
            siemplify.result.add_result_json(result.to_json())
        else:
            output_message = "Mail was sent successfully. Json result cannot be generated, since this is only " \
                             "supported in Exchange Server Version 2013 and above"

    except Exception as e:
        siemplify.LOGGER.error("General error performing action {}".format(SEND_MAIL_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Failed to send email! The Error is {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
