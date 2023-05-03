from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SentinelOneManager import SentinelOneManager, SentinelOneAgentNotFoundError
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import add_prefix_to_dict_keys, dict_to_flat, flat_dict_to_csv

# Consts.
SENTINEL_ONE_PROVIDER = 'SentinelOne'
SENTINEL_PREFIX = 'SENO_'
ADDRESS = EntityTypes.ADDRESS
HOSTNAME = EntityTypes.HOSTNAME


@output_handler
def main():
    # Define Variables.
    entities_successed = []
    errors_dict = {}
    result_value = False
    # Configuration.
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(SENTINEL_ONE_PROVIDER)
    sentinel_one_manager = SentinelOneManager(conf['Api Root'], conf['Username'], conf['Password'])

    # Get scope entities.
    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == ADDRESS or
                      entity.entity_type == HOSTNAME]

    # Run on entities.
    for entity in scope_entities:
        try:
            # Get endpoint agent id.
            if entity.entity_type == ADDRESS:
                agent_id = sentinel_one_manager.find_endpoint_agent_id(entity.identifier, by_ip_address=True)
            else:
                agent_id = sentinel_one_manager.find_endpoint_agent_id(entity.identifier)

            processes_list = sentinel_one_manager.get_agent_processes_list(agent_id, csv_output=True)

            if processes_list:
                entities_successed.append(entity)
                result_value = True
                # Add entity table.
                siemplify.result.add_entity_table(entity.identifier, processes_list)

        except SentinelOneAgentNotFoundError as err:
            errors_dict[entity.identifier] = unicode(err.message)

    if entities_successed:
        output_message = 'Found processes for: {0}'.format(",".join([entity.identifier for entity
                                                                     in entities_successed]))
    else:
        output_message = 'No processes were found for target entities.'

    # If were errors present them as a table.
    if errors_dict:
        # Produce error CSV.
        errors_csv = flat_dict_to_csv(errors_dict)
        # Draw table.
        siemplify.result.add_data_table('Unsuccessful Attempts', errors_csv)

    siemplify.update_entities(entities_successed)
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()

