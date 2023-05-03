from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from EmailManager import EmailManager
from base64 import b64encode

PROVIDER = "Email"
ACTIONS_NAME = 'Email_Get Mail EML File.'
EML_FILE_NAME_PATTERN = '{0}.eml'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTIONS_NAME

    # Configuration
    conf = siemplify.get_configuration(PROVIDER)
    from_address = conf["Sender's address"]
    imap_host = conf['IMAP Server Address']
    imap_port = str(conf['IMAP Port'])
    username = conf['Username']
    password = conf['Password']
    use_ssl = True if conf.get('IMAP USE SSL', 'false').lower() == 'true' else False

    email_manager = EmailManager(from_address)

    # IMAP Login
    email_manager.login_imap(host=imap_host, port=imap_port, username=username, password=password, use_ssl=use_ssl)

    message_id = siemplify.parameters.get("Message ID")
    is_result_value_base64 = siemplify.parameters.get("Base64 Encode", 'false').lower() == 'true'

    msg = email_manager.get_message_data_by_message_id(message_id, include_raw_eml=True)
    eml = msg.get('original_message', '')
    eml_base64 = b64encode(eml)

    siemplify.result.add_attachment(message_id, EML_FILE_NAME_PATTERN.format(message_id), eml)

    siemplify.end('Successfully fetched message EML',
                  eml_base64 if is_result_value_base64 else eml)


if __name__ == "__main__":
    main()



