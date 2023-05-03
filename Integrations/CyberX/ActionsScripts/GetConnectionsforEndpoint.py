from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv
from CyberXManager import CyberXManager

ACTION_NAME = 'CyberX_Get Connections for endpoint.'
PROVIDER = 'CyberX'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME

    config = siemplify.get_configuration(PROVIDER)
    api_root = config['API Root']
    access_token = config['Access Token']
    verify_ssl = config.get('Verify SSL', 'false').lower() == 'true'

    cyberx_manager = CyberXManager(api_root=api_root, access_token=access_token, verify_ssl=verify_ssl)

    result_value = False
    success_entities = []
    errors = []

    target_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS or
                       entity.entity_type == EntityTypes.HOSTNAME]

    for entity in target_entities:
        try:
            if entity.entity_type == EntityTypes.ADDRESS:
                device_id = cyberx_manager.get_device_id_by_address(entity.identifier)

            elif entity.entity_type == EntityTypes.HOSTNAME:
                device_id = cyberx_manager.get_device_id_by_host_name(entity.identifier)

            # If Device ID will not found an exception will be thrown from the manager.
            device_connections = cyberx_manager.get_device_connections(device_id)

            if device_connections:
                siemplify.result.add_entity_table(entity.identifier, flat_dict_to_csv(dict_to_flat(
                    device_connections)))
                result_value = True
                success_entities.append(entity)

        except Exception as err:
            error_message = 'Error occurred fetching connections for "{0}", ERROR: {1}'.format(
                entity.identifier,
                err.message
            )
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            errors.append(error_message)

    if success_entities:
        output_message = 'Fetched connection information for the following entities: {0}'.format(", ".join([
            entity.identifier for entity in success_entities]))
    else:
        output_message = 'No connections information found for target entities.'

    if errors:
        output_message = '{0} \n \n Errors: \n {1}'.format(
            output_message,
            '\n '.join(errors)
        )

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
