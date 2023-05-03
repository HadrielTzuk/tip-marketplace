from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from EmailManager import EmailManager


@output_handler
def main():
    siemplify = SiemplifyAction()
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

    # Login
    email_manager.login_smtp(host=smtp_host, port=smtp_port, username=username, password=password, use_ssl=use_ssl,
                             use_auth=use_auth)

    # Parameters
    send_to = siemplify.parameters['Recipients']  # 'email@example.com,email2@example.com'
    cc = siemplify.parameters.get('CC', "")
    bcc = siemplify.parameters.get('bcc', "")
    subject = siemplify.parameters['Subject']
    body = siemplify.parameters['Content']

    email_manager.send_mail_html_embedded_photos(send_to, subject, body, cc=cc, bcc=bcc,
                                                 display_sender_name=display_sender_name)

    output_message = "Mail sent successfully."
    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
