from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CyberarkVaultManager import CyberarkManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('CyberArkVault')
    username = conf['Username']
    password = conf['Password']
    use_ssl = conf['Use SSL']
    api_root = conf['Api Root']

    cyberark_manager = CyberarkManager(username, password, api_root, use_ssl)
    user_name = siemplify.parameters['User Name']

    user_details = cyberark_manager.get_user_details(user_name)

    # active_status True = Enable
    is_success = cyberark_manager.change_user_active_status(user_name, user_details, active_status=True)

    if is_success:
        output_message = 'User {0} was successfully enabled.'.format(user_name)
    else:
        output_message = "Can't enabled a user {0}.".format(user_name)

    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
