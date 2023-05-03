from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from PortnoxManager import PortnoxManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration("Portnox")
    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']
    use_ssl = str(conf.get('Verify SSL', 'False')).lower() == 'true'
    portnox_manager = PortnoxManager(api_root, username, password, use_ssl)
    device_id = siemplify.parameters['DeviceId']

    portnox_manager.revalidate_device(device_id)

    # Use the default timeout in manager consts
    portnox_manager.wait_for_device_revalidation(device_id)
    output_message = 'Device: {0} revalidation completed'.format(
        device_id)
    result_value = 'true'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
