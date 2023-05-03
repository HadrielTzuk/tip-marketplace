from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from FortiManager import FortiManager


PROVIDER = 'FortiManager'
ACTION_NAME = 'FortiManager_Ping'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    forti_manager = FortiManager(conf['API Root'], conf['Username'], conf['Password'], verify_ssl)

    siemplify.end('Connection Established!', True)


if __name__ == "__main__":
    main()
