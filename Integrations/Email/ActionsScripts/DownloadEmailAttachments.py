from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from EmailManager import EmailManager
import os


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Email - Download Attachments"

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

    # Parameters
    message_id = siemplify.parameters.get("Message ID")
    local_path = siemplify.parameters.get("Download Path")
    subject_filter = siemplify.parameters.get("Subject Filter")
    email_uid = siemplify.parameters.get("Email UID")
    only_unread = siemplify.parameters.get("Only Unread").lower() == 'true'
    attachments_local_paths = []

    # Create the local path dir if it doesn't exist
    if not os.path.exists(local_path):
        os.makedirs(local_path)

    if email_uid:
        filtered_mail_ids = [x.strip() for x in email_uid.split(',')]
    else:
        filtered_mail_ids = email_manager.receive_mail_ids(subject_filter=subject_filter, only_unread=only_unread,
                                                           message_id=message_id)

    for email_uid in filtered_mail_ids:
        try:
            # Get attachment name and content from email
            attachments = email_manager.extract_attachments(email_uid)
            for attachment_name, attachment_content in attachments.items():
                # Save to given path
                attachment_local_path = email_manager.save_attachment_to_local_path(local_path, attachment_name, attachment_content)
                attachments_local_paths.append(unicode(attachment_local_path).encode("utf-8"))
        except Exception as e:
            siemplify.LOGGER.error(
                "Unable to get attachment for {}: {}".format(unicode(email_uid).encode("utf-8"), str(e)))
            siemplify.LOGGER.exception(e)

    output_message = "Downloaded {0} attachments. \n\nFiles:\n{1}".format(len(attachments_local_paths), "\n".join(attachments_local_paths))
    siemplify.end(output_message, ",".join(attachments_local_paths))


if __name__ == "__main__":
    main()



