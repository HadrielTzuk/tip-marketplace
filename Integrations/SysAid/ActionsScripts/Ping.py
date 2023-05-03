from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SysAidManager import SysAidManager


PROVIDER = "SysAid"
ACTION_NAME = "SysAid - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL').lower() == 'true'
    sysaid_manager = SysAidManager(server_address=conf.get('Api Root'),
                                           username=conf.get('Username'),
                                           password=conf.get('Password'),
                                           verify_ssl=verify_ssl)

    siemplify.end('Connection Established', True)


if __name__ == "__main__":
    main()