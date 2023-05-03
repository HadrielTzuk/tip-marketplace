from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from exceptions import SentinelOneV2NotFoundError
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyUtils import add_prefix_to_dict_keys
from TIPCommon import extract_configuration_param, extract_action_param, flat_dict_to_csv
from utils import get_entity_original_identifier
from constants import INTEGRATION_NAME, ENRICH_ENDPOINTS_SCRIPT_NAME, UNSUCCESSFUL_ATTEMPTS_TABLE_NAME, \
    SENTINEL_PREFIX, PRODUCT_NAME
from SentinelOneV2Factory import SentinelOneV2ManagerFactory


SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME, EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_ENDPOINTS_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    create_insight = extract_action_param(siemplify, param_name='Create Insight', default_value=True,
                                          input_type=bool, print_value=True)
    infected_endpoint_insights = extract_action_param(siemplify, param_name='Only Infected Endpoints Insights',
                                                      input_type=bool, default_value=True, print_value=True)

    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    success_entities, failed_entities, json_result, errors_dict = [], [], [], {}
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        sentinel_one_manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                                         verify_ssl=verify_ssl,
                                                                         force_check_connectivity=True)
        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)

            try:
                siemplify.LOGGER.info('Processing entity {}'.format(entity_identifier))
                found_agent = None

                # Get endpoint agent id.
                if entity.entity_type == EntityTypes.HOSTNAME:
                    try:
                        siemplify.LOGGER.info('Fetching agent for hostname {}'.format(entity_identifier))
                        found_agent = sentinel_one_manager.get_agent_by_hostname(entity_identifier)
                    except SentinelOneV2NotFoundError as e:
                        failed_entities.append(entity)
                        siemplify.LOGGER.info(e)
                        siemplify.LOGGER.info('Skipping entity {}'.format(entity_identifier))
                        continue

                elif entity.entity_type == EntityTypes.ADDRESS:
                    try:
                        siemplify.LOGGER.info('Fetching agent for address {}'.format(entity_identifier))
                        found_agent = sentinel_one_manager.get_agent_by_ip(entity_identifier)
                    except SentinelOneV2NotFoundError as e:
                        failed_entities.append(entity)
                        siemplify.LOGGER.info(e)
                        siemplify.LOGGER.info('Skipping entity {}'.format(entity_identifier))
                        continue

                if found_agent:
                    json_result.append(found_agent.to_json())
                    siemplify.LOGGER.info('Found agent {} for entity {}'.format(found_agent.id, entity_identifier))
                    siemplify.result.add_entity_table(entity_identifier, found_agent.to_csv())
                    # Enrich entity.
                    entity.additional_properties.update(add_prefix_to_dict_keys(found_agent.to_flat(),
                                                                                SENTINEL_PREFIX))
                    if create_insight and not infected_endpoint_insights:
                        siemplify.add_entity_insight(entity, found_agent.to_insight())
                    elif infected_endpoint_insights and found_agent.infected:
                        siemplify.add_entity_insight(entity, found_agent.to_insight())

                    success_entities.append(entity)

            except Exception as e:
                siemplify.LOGGER.error(e)
                siemplify.LOGGER.exception(e)
                errors_dict[entity_identifier] = str(e)

        if success_entities:
            siemplify.result.add_result_json(json_result)
            siemplify.update_entities(success_entities)
            output_message = 'Successfully retrieved information about the following endpoints from {}:\n{}\n'\
                .format(PRODUCT_NAME, ', '.join([get_entity_original_identifier(entity)
                                                 for entity in success_entities]))
            if failed_entities:
                output_message += 'Action wasn\'t able to retrieve information about the following endpoints from {}:' \
                                  '\n{}\n'.format(PRODUCT_NAME, ', '.join([get_entity_original_identifier(entity)
                                                  for entity in failed_entities]))
        else:
            result_value = False
            output_message = 'No information was retrieved for the provided entities.'

        if errors_dict:
            siemplify.result.add_data_table(UNSUCCESSFUL_ATTEMPTS_TABLE_NAME, flat_dict_to_csv(errors_dict))

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(ENRICH_ENDPOINTS_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
