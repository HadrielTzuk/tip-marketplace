from SiemplifyUtils import output_handler
from XForceManager import XForceManager
from SiemplifyAction import SiemplifyAction


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('XForce')
    address = conf['Address']
    api_key = conf['Api Key']
    api_password = conf['Api Password']
    verify_ssl = conf['Verify SSL'].lower() == 'true'
    xforce_manager = XForceManager(api_key, api_password, address, verify_ssl=verify_ssl)

    connectivity = xforce_manager.test_connectivity()
    output_message = "Connected Successfully"
    siemplify.end(output_message, connectivity)


if __name__ == '__main__':
    main()
