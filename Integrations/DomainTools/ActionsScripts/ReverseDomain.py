from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import *
from DomainToolsManager import DomainToolsManager
from SiemplifyUtils import *

# Consts
DOMAINTOOLS_PREFIX = 'DT'
HOSTNAME = EntityTypes.HOSTNAME
URL = EntityTypes.URL


@output_handler
def main():

    # Configurations
    siemplify = SiemplifyAction()
    configuration_settings = siemplify.get_configuration('DomainTools')
    username = configuration_settings['Username']
    api_key = configuration_settings['ApiToken']
    domaintools_manager = DomainToolsManager(username, api_key)

    # Variables Definition.
    output_message = ''
    entities_to_update = []
    result_value = False

    #  Get scope entities.
    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == HOSTNAME and
                      not entity.is_internal or entity.entity_type == URL]

    for entity in scope_entities:
        # Extract doamin from entity.
        extracted_domain = domaintools_manager.extract_domain_from_string(entity.identifier)

        # Get response
        res = domaintools_manager.enrichDomain(extracted_domain)

        if res:
            # Push entity to entities to update array.
            entities_to_update.append(entity)
            # Convert response dict to flat dict.
            flat_dict_res = dict_to_flat(res)
            # Convert response to CSV format string list.
            csv_res = flat_dict_to_csv(flat_dict_res)
            # Enrich Entity.
            entity.additional_properties.update(add_prefix_to_dict(flat_dict_res, DOMAINTOOLS_PREFIX))
            # Print table to result action view.
            siemplify.result.add_entity_table(entity.identifier, csv_res)
            # Return true on action result.
            result_value = True
        else:
            pass

    # Update Entities.
    siemplify.update_entities(entities_to_update)

    # Organize output message.
    if entities_to_update:
        output_message = '{0} : enriched by DomainTools.'.format(", ".join(map(str, entities_to_update)))
    else:
        output_message = 'No entities were enriched.'

    # End action
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
