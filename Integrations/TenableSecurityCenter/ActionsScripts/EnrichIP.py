from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from TenableManager import TenableSecurityCenterManager
from SiemplifyUtils import dict_to_flat, add_prefix_to_dict_keys, convert_dict_to_json_result_dict
import json

SCRIPT_NAME = "TenableSecurityCenter - EnrichIP"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration('TenableSecurityCenter')
    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']
    use_ssl = conf['Use SSL'].lower() == 'true'
    repo_name= siemplify.parameters['Repository Name']

    tenable_manager = TenableSecurityCenterManager(server_address, username, password, use_ssl)

    enriched_entities = []
    json_results = {}

    for entity in siemplify.target_entities:
        try:
            if entity.entity_type == EntityTypes.ADDRESS:
                ip_info = tenable_manager.get_ip_info(entity.identifier, repo_name)
                json_results[entity.identifier] = ip_info

                ip_info = add_prefix_to_dict_keys(dict_to_flat(ip_info), 'Tenable')

                entity.is_enriched = True

                entity.additional_properties.update(ip_info)

                enriched_entities.append(entity)

        except Exception as e:
            # An error occurred - skip entity and continue
            siemplify.LOGGER.error(
                "An error occurred on entity: {}.\n{}.".format(
                    entity.identifier, str(e)
                ))
            siemplify.LOGGER._log.exception(e)


    if enriched_entities:
        entities_names = [entity.identifier for entity in enriched_entities]
        output_message = 'Tenable: The following entities were enriched:\n' + '\n'.join(
            entities_names)
        siemplify.update_entities(enriched_entities)

    else:
        output_message = 'Tenable: No entities were enriched.'

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, 'true')


if __name__ == "__main__":
    main()
