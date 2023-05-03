from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CiscoFirepowerManager import CiscoFirepowerManager
from SiemplifyDataModel import EntityTypes

INTEGRATION_PROVIDER = 'CiscoFirepowerManagementCenter'


@output_handler
def main():

    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(INTEGRATION_PROVIDER)
    verify_ssl = str(conf.get('Verify SSL', 'false').lower()) == str(True).lower()

    cisco_firepower_manager = CiscoFirepowerManager(conf['API Root'],
                                                    conf['Username'],
                                                    conf['Password'],
                                                    verify_ssl)
    # Parameters.
    network_group_name = siemplify.parameters.get('Network Group Name')

    # variables.
    error_flag = False
    blocked_entities = []
    errors = []
    result_value = False

    # Set script name.
    siemplify.script_name = 'CiscoFirepower_Unblock_Address'

    target_addresses = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

    # Get url group object to pass to the block function.
    network_group_object = cisco_firepower_manager.get_network_group_object_by_name(network_group_name)

    for address_entity in target_addresses:
        try:
            cisco_firepower_manager.unblock_ip_address(network_group_object, address_entity.identifier)
            result_value = True
            blocked_entities.append(address_entity.identifier)
        except Exception as err:
            error_message = 'Error unblocking address "{0}", ERROR: {1}.'.format(address_entity.identifier,
                                                                                      err.message)

            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            error_flag = True
            errors.append(error_message)

    if result_value:
        output_message = 'The following entities were unblocked: {0}'.format(','.join(blocked_entities))
    else:
        output_message = 'No entities were unblocked.'

    if error_flag:
        output_message = "{0}  \n \n  ERRORS: {1}".format(output_message, " \n ".join(errors))

    siemplify.end(output_message, True)


if __name__ == '__main__':
    main()
