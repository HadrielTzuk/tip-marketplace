from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from IBossManager import IBossManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, add_prefix_to_dict
from constants import ADD_IP_TO_POLICY_BLOCK_LIST, INTEGRATION_NAME, DIRECTION_MAPPER, POLICY_BLOCKED_ENRICHMENT_NAME, ENRICHMENT_PREFIX
from exceptions import ListIsNotBlockListException

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_IP_TO_POLICY_BLOCK_LIST
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # Configuration
    cloud_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Cloud API Root',
                                           is_mandatory=True)
    account_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Account API Root',
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    category_id = extract_action_param(siemplify, param_name='Category ID', is_mandatory=True, print_value=True)
    priority = extract_action_param(siemplify, param_name='Priority', is_mandatory=True, input_type=int,
                                    print_value=True)
    direction = extract_action_param(siemplify, param_name='Direction', is_mandatory=True, print_value=True)
    start_port = extract_action_param(siemplify, param_name='Start Port', input_type=int, print_value=True)
    end_port = extract_action_param(siemplify, param_name='End Port', input_type=int, print_value=True)
    note = extract_action_param(siemplify, param_name='Note', print_value=True)
    is_regex = extract_action_param(siemplify, param_name='Is Regular Expression', input_type=bool, print_value=True)

    direction = DIRECTION_MAPPER.get(direction, 0)
    is_regex = int(is_regex)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    enriched_entities = []
    output_message = ''
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]
    try:
        manager = IBossManager(cloud_api_root, account_api_root, username, password, verify_ssl, siemplify.LOGGER)
        manager.validate_if_block_list(category_id)

        for entity in suitable_entities:
            try:
                siemplify.LOGGER.info('\n\nStarted processing entity: {}'.format(entity.identifier))
                manager.add_ip_to_block_list(entity.identifier, category_id, priority, direction, start_port, end_port,
                                             note, is_regex)
                enriched_entities.append(entity)
                entity.additional_properties.update(add_prefix_to_dict({POLICY_BLOCKED_ENRICHMENT_NAME: "True"}, ENRICHMENT_PREFIX))
                entity.is_enriched = True
                siemplify.LOGGER.info('Successfully blocked the following IP {}'.format(entity.identifier))
            except Exception as e:
                failed_entities.append(entity.identifier)
                if entity.identifier not in enriched_entities:
                    siemplify.LOGGER.error(
                        'Action was not able to block the following IP:  \n {}'.format(entity.identifier))
                else:
                    siemplify.LOGGER.error('Failed to add enrichment field {} to entity: {}'.format(
                        POLICY_BLOCKED_ENRICHMENT_NAME, entity.identifier))
                siemplify.LOGGER.exception(e)
            siemplify.LOGGER.info('Finished processing entity: {}'.format(entity.identifier))

        if failed_entities:
            output_message += 'Action was not able to block the following IPs in the iBoss category with ID {}: \n{}\n'.format(
                category_id, '\n'.join(failed_entities))

        if enriched_entities:
            output_message += 'Successfully blocked the following IPs in the iBoss category with ID {} \n{}\n'.format(
                category_id, '\n'.join([entity.identifier for entity in enriched_entities]))
            siemplify.update_entities(enriched_entities)

        else:
            output_message = 'No IPs were blocked in the iBoss category with ID {}.'.format(category_id)
            siemplify.LOGGER.info(output_message)
            result_value = False

    except ListIsNotBlockListException:
        output_message = "Category with ID {} is not associated with a Block list.".format(category_id)
        siemplify.LOGGER.info(output_message)
        result_value = False
    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(ADD_IP_TO_POLICY_BLOCK_LIST, e)
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
