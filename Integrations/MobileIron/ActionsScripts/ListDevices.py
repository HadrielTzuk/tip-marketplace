from SiemplifyUtils import output_handler
# Imports
from MobileIronManager import MobileIronManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, construct_csv
import json

# Consts.
PROVIDER_NAME = 'MobileIron'
ACTION_NAME = 'MobileIron_List Devices'
TABLE_HEADER = 'Devices'


@output_handler
def main():
    # Variables Definition.
    devices_json = '[]'

    # Configuration.
    siemplify = SiemplifyAction()
    siemplify.script_name = ""
    configuretion_settings = siemplify.get_configuration(PROVIDER_NAME)
    api_root = configuretion_settings['API Root']
    username = configuretion_settings['Username']
    password = configuretion_settings['Password']
    admin_device_id = configuretion_settings.get('Admin Device ID', 1)
    connected_cloud = configuretion_settings.get('Cloud Instance', 'false').lower() == 'true'
    verify_ssl = configuretion_settings.get('Verify SSL', 'false').lower() == 'true'

    mobile_iron_manager = MobileIronManager(api_root, username, password,
                                            admin_device_id, connected_cloud,
                                            verify_ssl)

    # Parameters.
    fields_to_fetch = siemplify.parameters.get('Fields To Fetch')

    devices = mobile_iron_manager.fetch_devices(fields_to_fetch=fields_to_fetch)

    if devices:
        flat_devices = map(dict_to_flat, devices)
        devices_csv = construct_csv(flat_devices)
        siemplify.result.add_data_table(TABLE_HEADER, devices_csv)
        output_message = 'Found "{0}" devices.'.format(len(flat_devices))
        devices_json = json.dumps(devices)
    else:
        output_message = 'No devices were found.'

    siemplify.end(output_message, devices_json)


if __name__ == '__main__':
    main()
