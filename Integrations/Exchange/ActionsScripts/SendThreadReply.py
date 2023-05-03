from ExchangeActions import extract_action_parameter, init_manager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import convert_comma_separated_to_list
from constants import INTEGRATION_NAME, SEND_THREAD_REPLY_SCRIPT_NAME

from requests.exceptions import ConnectionError
from exceptions import ExchangeManagerError


@output_handler
def main():
    siemplify = SiemplifyAction()

    message_id = extract_action_parameter(
        siemplify,
        param_name="Message ID",
        is_mandatory=True,
        print_value=True
    )
    folder_names_string = extract_action_parameter(
        siemplify,
        param_name="Folder Name",
        default_value="Inbox",
        is_mandatory=True,
        print_value=True
    )
    content = extract_action_parameter(
        siemplify,
        param_name="Content",
        is_mandatory=True
    )
    attachment_paths_string = extract_action_parameter(
        siemplify,
        param_name="Attachments Paths",
        print_value=True
    )
    reply_all = extract_action_parameter(
        siemplify,
        param_name="Reply All",
        input_type=bool,
        print_value=True
    )
    reply_to_string = extract_action_parameter(
        siemplify,
        param_name="Reply To"
    )

    folder_names = convert_comma_separated_to_list(folder_names_string)
    attachment_paths = (
        convert_comma_separated_to_list(attachment_paths_string)
        if attachment_paths_string
        else []
    )
    reply_to = (
        convert_comma_separated_to_list(reply_to_string)
        if reply_to_string
        else []
    )

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = f"Successfully sent reply to the message with ID {message_id} ."

    try:
        # Create new exchange manager instance
        em = init_manager(siemplify, INTEGRATION_NAME)
        original_mail = None

        for folder in folder_names:
            try:
                filtered_messages = em.receive_mail(message_id=message_id, folder_name=folder)
                if filtered_messages:
                    # since we are fetching by message_id we should get only first (and only?) one
                    original_mail = filtered_messages[0]

            except (ConnectionError, ExchangeManagerError):
                raise

            except Exception as e:
                siemplify.LOGGER.error(f"Failed to get email from folder={folder} "
                                       f"with message_id={message_id}")
                siemplify.LOGGER.exception(e)

        if original_mail is None:
            raise Exception(f"The provided message id {message_id} was not "
                            f"found in folders {folder_names}.")

        if reply_all:
            to_recipients_emails = (
                [rec.email_address for rec in original_mail.to_recipients]
                if original_mail.to_recipients
                else []
            )
            cc_recipients_emails = (
                [cc.email_address for cc in original_mail.cc_recipients]
                if original_mail.cc_recipients
                else []
            )

            addresses = list(set(
                to_recipients_emails +
                [original_mail.author.email_address, ] +
                cc_recipients_emails
            ))

            if not addresses:
                raise Exception("If you want to send a reply only to your own email address, "
                                "you need to work with \"Reply To\" parameter.")
        elif reply_to:
            addresses = reply_to
        else:
            addresses = [original_mail.author.email_address, ]

        result = em.send_mail_html_embedded_photos(
            to_addresses=",".join(addresses),
            html_body=content,
            subject=original_mail.subject,
            attachments_paths=attachment_paths,
            reply_to_recipients=addresses,
            original_mail=original_mail
        )
        siemplify.result.add_result_json(result.to_json())

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {SEND_THREAD_REPLY_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action \"Send Thread Reply\". Reason: {e}"

    siemplify.LOGGER.info(
        f"status: {status}\n  "
        f"result_value: {result_value}\n  "
        f"output_message: {output_message}"
    )
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
