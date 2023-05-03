from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from EmailManager import EmailManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    # Configuration
    conf = siemplify.get_configuration("Email")
    from_address = conf["Sender's address"]

    email_manager = EmailManager(from_address)

    smtp_host = conf['SMTP Server Address']
    smtp_port = str(conf['SMTP Port'])
    username = conf['Username']
    password = conf['Password']
    smtp_use_ssl = True if conf['SMTP USE SSL'] == 'True' else False
    use_auth = True if conf['SMTP Use Authentication'] == 'True' else False
    imap_host = conf['IMAP Server Address']
    imap_port = str(conf['IMAP Port'])
    imap_use_ssl = True if conf['IMAP USE SSL'] == 'True' else False
    smtp = email_manager.login_smtp(host=smtp_host, port=smtp_port, username=username, password=password,
                                    use_ssl=smtp_use_ssl, use_auth=use_auth)

    # Verify imap host is configure
    if imap_host.strip(" "):
        imap = email_manager.login_imap(host=imap_host, port=imap_port, username=username, password=password,
                                        use_ssl=imap_use_ssl)

    output_message = "Connected successfully"
    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()