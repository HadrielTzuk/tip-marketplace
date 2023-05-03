from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from exceptions import SentinelOneV2NotFoundError
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, flat_dict_to_csv
from utils import get_entity_original_identifier
from constants import (
    INTEGRATION_NAME,
    RECONNECT_AGENT_TO_THE_NETWORK_SCRIPT_NAME,
    UNSUCCESSFUL_ATTEMPTS_TABLE_NAME,
)
from SentinelOneV2Factory import SentinelOneV2ManagerFactory

SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME, EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RECONNECT_AGENT_TO_THE_NETWORK_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    success_entities, errors_dict = [], {}
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        sentinel_one_manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                                         verify_ssl=verify_ssl,
                                                                         force_check_connectivity=True)

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            try:
                siemplify.LOGGER.info("Processing entity {}".format(entity_identifier))
                found_agent = None

                # Get endpoint agent id.
                if entity.entity_type == EntityTypes.HOSTNAME:
                    try:
                        siemplify.LOGGER.info("Fetching agent for hostname {}".format(entity_identifier))
                        found_agent = sentinel_one_manager.get_agent_by_hostname(hostname=entity_identifier)
                    except SentinelOneV2NotFoundError as e:
                        siemplify.LOGGER.info(e)
                        siemplify.LOGGER.info("Skipping entity {}".format(entity_identifier))
                        continue

                elif entity.entity_type == EntityTypes.ADDRESS:
                    try:
                        siemplify.LOGGER.info("Fetching agent for address {}".format(entity_identifier))
                        found_agent = sentinel_one_manager.get_agent_by_ip(ip_address=entity_identifier)
                    except SentinelOneV2NotFoundError as e:
                        siemplify.LOGGER.info(e)
                        siemplify.LOGGER.info("Skipping entity {}".format(entity_identifier))
                        continue

                if found_agent:
                    siemplify.LOGGER.info("Found agent {} for entity {}".format(found_agent.id, entity_identifier))
                    siemplify.LOGGER.info("Connecting agent {} from network.".format(found_agent.id))

                    if sentinel_one_manager.reconnect_agent_to_network(found_agent.id):
                        success_entities.append(entity_identifier)
                else:
                    siemplify.LOGGER.error('Error: Not found id for entity "{}"'.format(entity_identifier))

            except Exception as e:
                siemplify.LOGGER.error(e)
                siemplify.LOGGER.exception(e)
                errors_dict[entity_identifier] = str(e)

        if success_entities:
            output_message = 'The following entities were reconnected to the network: {}' \
                .format(', '.join(success_entities))
        else:
            result_value = False
            output_message = 'No target entities were reconnected from the network.'

        # If were errors present them as a table.
        if errors_dict:
            siemplify.result.add_data_table(UNSUCCESSFUL_ATTEMPTS_TABLE_NAME, flat_dict_to_csv(errors_dict))

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(RECONNECT_AGENT_TO_THE_NETWORK_SCRIPT_NAME, e)
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
