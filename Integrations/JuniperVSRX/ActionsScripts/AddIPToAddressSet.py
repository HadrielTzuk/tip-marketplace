from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from JuniperVSRXManager import JuniperVSRXManager

PROVIDER_NAME = 'JuniperVSRX'
ACTION_NAME = 'JuniperVSRX Add IP To Address Set'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    config = siemplify.get_configuration(PROVIDER_NAME)
    address = config['Address']
    port = config['Port']
    username = config['Username']
    password = config['Password']

    juniper_manager = JuniperVSRXManager(address, port, username, password)
    result_value = False
    errors = []
    success_entities = []

    # Parameters.
    address_set_name = siemplify.parameters.get('Address Set Name')
    zone_name = siemplify.parameters.get('Zone Name')

    address_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

    for entity in address_entities:
        try:
            juniper_manager.add_ip_to_address_set(entity.identifier, address_set_name, zone_name)
            success_entities.append(entity)
        except Exception as err:
            error_message = 'Error adding address "{0}" to address-set "{1}", ERROR: {2}'.format(
                entity.identifier,
                address_set_name,
                err.message
            )
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            errors.append(error_message)

    juniper_manager.commit_config_changes()
    juniper_manager.close_session()

    if success_entities:
        output_message = '{0} were added to address-set "{1}"'.format(
            ", ".join([entity.identifier for entity in success_entities]),
            address_set_name
        )
        result_value = True
    else:
        output_message = 'No entities were added to address-set "{0}"'.format(address_set_name)

    if errors:
        output_message = '{0}, \n \n Errors: {1}'.format(
            output_message,
            "\n ".join(errors)
        )

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
