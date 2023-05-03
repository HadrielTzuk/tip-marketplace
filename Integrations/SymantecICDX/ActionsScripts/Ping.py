from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecICDXManager import SymantecICDXManager


PROVIDER = "SymantecICDX"
ACTION_NAME = "SymantecICDX - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get('Verify SSL').lower() == 'true'
    icdx_manager = SymantecICDXManager(api_root=conf.get('Api Root'),
                                       api_key=conf.get('Api Token'),
                                       verify_ssl=verify_ssl)

    icdx_manager.test_connectivity()
    siemplify.end('Connection Established', True)


if __name__ == "__main__":
    main()
