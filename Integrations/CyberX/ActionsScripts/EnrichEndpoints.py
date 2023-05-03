from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv, add_prefix_to_dict
from CyberXManager import CyberXManager

ACTION_NAME = 'CyberX_Enrich Endpoint'
PROVIDER = 'CyberX'
CYBERX_PREFIX = 'CX_'


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
    endpoint_information = None
    success_entities = []
    errors = []

    target_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS or
                       entity.entity_type == EntityTypes.HOSTNAME]

    for entity in target_entities:
        try:
            if entity.entity_type == EntityTypes.ADDRESS:
                endpoint_information = cyberx_manager.get_device_by_ip_address(entity.identifier)
            elif entity.entity_type == EntityTypes.HOSTNAME:
                endpoint_information = cyberx_manager.get_device_by_host_name(entity.identifier)

            if endpoint_information:
                siemplify.result.add_entity_table(entity.identifier, flat_dict_to_csv(dict_to_flat(
                    endpoint_information)))
                entity.additional_properties.update(add_prefix_to_dict(dict_to_flat(endpoint_information),
                                                                       CYBERX_PREFIX))
                result_value = True
                success_entities.append(entity)
        except Exception as err:
            error_message = 'Error occurred fetching endpoint data for "{0}", ERROR: {1}'.format(
                entity.identifier,
                err.message
            )
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            errors.append(error_message)

    if success_entities:
        output_message = 'The following entities were enriched: {0}'.format(", ".join([entity.identifier for
                                                                                       entity in success_entities]))
    else:
        output_message = 'No entities were enriched.'

    if errors:
        output_message = '{0} \n \n Errors: \n {1}'.format(
            output_message,
            '\n '.join(errors)
        )

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
