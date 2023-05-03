from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from MXToolBoxManager import MXToolBoxManager
from SiemplifyUtils import dict_to_flat, construct_csv, get_domain_from_entity, convert_dict_to_json_result_dict

MXTOOLBOX_PROVIDER = 'MXToolBox'
SCRIPT_NAME = 'MXToolBox_MX_Lookup'


@output_handler
def main():
    # Configurations.
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration(MXTOOLBOX_PROVIDER)
    verify_ssl = conf['Verify SSL'].lower() == 'true'
    mx_tool_box_manager = MXToolBoxManager(conf['API Root'], conf['API Key'], verify_ssl)

    # Variables.
    errors = []
    success_entities = []
    mx_domains = []
    result_value = False
    json_results = {}
    target_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.HOSTNAME or
                       entity.entity_type == EntityTypes.URL or entity.entity_type == EntityTypes.USER]

    for entity in target_entities:
        try:
            result = mx_tool_box_manager.domain_mx_lookup(get_domain_from_entity(entity))
            if result:
                json_results[entity.identifier] = result
                success_entities.append(entity)
                result_value = True
                result = map(dict_to_flat, result)
                mx_domains.append(result[0].get('Hostname'))
                entity.additional_properties.update({"MX_Hostnames": " | ".join([record.get('Hostname') for record in
                                                                                 result])})
                entity.is_enriched = True
                siemplify.result.add_entity_table(entity.identifier, construct_csv(result))

        except Exception as e:
            # An error occurred - skip entity and continue
            error_message = "An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e))
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(e)
            errors.append(error_message)

    if result_value:
        output_message = "The following domains were resolved: {0}".format(", ".join([entity.identifier for entity in success_entities]))
    else:
        output_message = 'Not found data for target entities.'

    if errors:
        output_message = "{0}  \n \n {1}".format(output_message, " \n ".join(errors))

    siemplify.update_entities(success_entities)

    # add json
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    siemplify.end(output_message, ",".join(mx_domains))


if __name__ == '__main__':
    main()
