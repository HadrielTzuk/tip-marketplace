from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoFirepowerManager import CiscoFirepowerManager
from SiemplifyUtils import construct_csv

INTEGRATION_PROVIDER = 'CiscoFirepowerManagementCenter'
SCRIPT_NAME = "CiscoFirepowerManagementCenter_Get Addresses List By Name"
CSV_TABLE_HEADER = "{0} Addresses List."

# Product's JSON structure.
LITERALS_KEY = 'literals'
VALUE_KEY = 'value'


@output_handler
def main():

    siemplify = SiemplifyAction()

    # Set script name.
    siemplify.script_name = SCRIPT_NAME

    conf = siemplify.get_configuration(INTEGRATION_PROVIDER)
    verify_ssl = str(conf.get('Verify SSL', 'false').lower()) == str(True).lower()

    cisco_firepower_manager = CiscoFirepowerManager(conf['API Root'],
                                                    conf['Username'],
                                                    conf['Password'],
                                                    verify_ssl)
    result_value = 'false'

    # Parameters.
    network_group_name = siemplify.parameters.get('Network Group Name')

    # Get url group object to pass to the block function.
    network_group_object = cisco_firepower_manager.get_network_group_object_by_name(network_group_name)

    siemplify.result.add_result_json(network_group_object)

    if network_group_object.get(LITERALS_KEY):
        siemplify.result.add_data_table(CSV_TABLE_HEADER.format(network_group_name), construct_csv(
            network_group_object.get(LITERALS_KEY)))
        output_message = 'Found addresses for the following list: {0}'.format(network_group_name)
        result_value = ",".join([address_obj.get(VALUE_KEY) for address_obj in network_group_object.get(LITERALS_KEY)])

    else:
        output_message = 'No addresses were found for group: {0}'.format(network_group_name)

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
