from SiemplifyUtils import output_handler
# -*- coding: utf-8 -*-
import sys
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
from EmailManager import EmailManager, SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY
from EmailStringUtils import safe_str_cast
from EmailCommon import EmailCommon, ProviderKeys, DEAFULT_RESOLVED_BODY
from SiemplifyUtils import convert_dict_to_json_result_dict


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Email - Send and Wait"
    # Configuration
    conf = siemplify.get_configuration("Email")
    from_address = conf["Sender's address"]
    smtp_host = conf['SMTP Server Address']
    smtp_port = str(conf['SMTP Port'])
    username = conf['Username']
    password = conf['Password']
    use_ssl = True if conf['SMTP USE SSL'] == 'True' else False
    use_auth = True if conf['SMTP Use Authentication'] == 'True' else False

    display_sender_name = conf.get("Sender's Display Name", "") if conf.get("Sender's Display Name") else None

    email_manager = EmailManager(from_address)

    # SMTP Login
    email_manager.login_smtp(host=smtp_host, port=smtp_port, username=username, password=password, use_ssl=use_ssl,
                             use_auth=use_auth)

    # Parameters
    send_to = siemplify.parameters['Recipients']  # 'email@example.com,email2@example.com'
    cc = siemplify.parameters.get('CC', "")
    bcc = siemplify.parameters.get('bcc', "")
    body = siemplify.parameters['Content']
    # Create unique subject
    subject = siemplify.parameters['Subject']

    msg_id = email_manager.send_mail_html_embedded_photos(send_to, subject, body, cc=cc, bcc=bcc,
                                                          display_sender_name=display_sender_name)

    siemplify.LOGGER.info("Mail sent successfully.")

    output_message = "Mail sent successfully."
    siemplify.end(output_message, msg_id, EXECUTION_STATE_INPROGRESS)


def query_job():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Email - Send and Wait"
    # Configuration
    conf = siemplify.get_configuration("Email")
    from_address = conf["Sender's address"]
    imap_host = conf['IMAP Server Address']
    imap_port = str(conf['IMAP Port'])
    username = conf['Username']
    password = conf['Password']
    use_ssl = True if conf['IMAP USE SSL'] == 'True' else False

    email_manager = EmailManager(from_address)

    # IMAP Login
    email_manager.login_imap(host=imap_host, port=imap_port, username=username, password=password, use_ssl=use_ssl)
    email_common = EmailCommon(siemplify.LOGGER)
    # Extract mail subject
    msg_id = siemplify.parameters["additional_data"]

    subject_exclude_pattern = siemplify.parameters.get('Exclusion Subject Regex')
    body_exclude_pattern = siemplify.parameters.get('Exclusion Body Regex')

    recipients_list = siemplify.parameters.get('Recipients', '').split(',')

    # Can filter also by: folder_name, content_filter, time_filter, only_unread.
    siemplify.LOGGER.info("Receiving mails.")
    recipients_responses = {}

    filtered_mail_ids = email_manager.receive_mail_ids(reply_to=msg_id)

    siemplify.LOGGER.info("Found {0} replies, with IDs: {1}, for message uid: {2}".format(len(filtered_mail_ids),
                                                                                          filtered_mail_ids,
                                                                                          msg_id))

    messages_content = [email_manager.get_message_data_by_message_id(mail_id, include_raw_eml=True,
                                                                     convert_body_to_utf8=True,
                                                                     convert_subject_to_utf8=True) for mail_id in filtered_mail_ids]

    siemplify.LOGGER.info("Running on recipients: {0}, message ID: {1}".format(",".join(recipients_list), msg_id))

    for recipient in recipients_list:
        siemplify.LOGGER.info("Running on recipient: {0}, message ID: {1}".format(recipient, msg_id))
        message = email_common.get_user_first_valid_message(recipient, messages_content,
                                                            subject_exclude_pattern, body_exclude_pattern)

        siemplify.LOGGER.info("Got message for recipient: {0}, message ID: {1}".format(recipient, msg_id))

        recipients_responses[recipient] = message
    siemplify.LOGGER.info(unicode(recipients_responses).decode('utf-8'))

    first_valid_response = next(((recipient, message) for recipient, message in recipients_responses.items()
                                 if message), None)

    if not first_valid_response:
        output_message = "Continuing...waiting for response, searching IN-REPLY-TO {0}".format(msg_id)
        siemplify.LOGGER.info(output_message)
        siemplify.end(output_message, msg_id, EXECUTION_STATE_INPROGRESS)
    else:
        recipient, message = first_valid_response[0], first_valid_response[1]

        json_result = convert_dict_to_json_result_dict({recipient: message})

        siemplify.result.add_result_json(json_result)

        # Build result values.
        output_message, result_value = build_result_objects(siemplify, message)

        siemplify.end(output_message, result_value, EXECUTION_STATE_COMPLETED)


def build_result_objects(siemplify, message):
    """
    Generate output message from received message.
    output_message should be first email body (full thread) + handle unicode\str encoding as needed
    :param siemplify: {SiemplifyAction} SiemplifyAction instance.
    :param email_manager: {EmailManager} Email Manager object.
    :param message: {dict} Received message dict.
    :return: {string} Action output.
    """
    body = message.get(SIEMPLIFY_MAIL_DICT_RESOLVED_BODY_KEY, DEAFULT_RESOLVED_BODY)

    body = safe_str_cast(body, DEAFULT_RESOLVED_BODY)

    try:
        # Extract response content without the forwarding part
        result_value = body[:(body.index('<'))]
    except Exception as e:
        siemplify.LOGGER.error("Failed to extract response content without the forwarding part")
        siemplify.LOGGER.exception(str(e))
        result_value = body

    output_message = "Response:\n{0}".format(body)

    return output_message, result_value


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        query_job()
