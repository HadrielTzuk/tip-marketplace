from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from exceptions import SentinelOneV2NotFoundError
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param, flat_dict_to_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, INITIATE_FULL_SCAN_SCRIPT_NAME, PRODUCT_NAME, UNSUCCESSFUL_ATTEMPTS_TABLE_NAME
from utils import get_entity_original_identifier
from SentinelOneV2Factory import SentinelOneV2ManagerFactory

SUPPORTED_ENTITY_TYPES = [EntityTypes.HOSTNAME, EntityTypes.ADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = INITIATE_FULL_SCAN_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities = [], []
    errors_dict = {}

    try:
        sentinel_one_manager = SentinelOneV2ManagerFactory().get_manager(api_root=api_root, api_token=api_token,
                                                                         verify_ssl=verify_ssl,
                                                                         force_check_connectivity=True)
        for entity in scope_entities:
            entity_identifier = get_entity_original_identifier(entity)
            try:
                siemplify.LOGGER.info("Processing entity {}".format(entity_identifier))
                agent = None
                if entity.entity_type == EntityTypes.HOSTNAME:
                    try:
                        siemplify.LOGGER.info("Fetching agent for hostname {}".format(entity_identifier))
                        agent = sentinel_one_manager.get_agent_by_hostname(hostname=entity_identifier)
                    except SentinelOneV2NotFoundError as e:
                        failed_entities.append(entity_identifier)
                        siemplify.LOGGER.info(e)
                        siemplify.LOGGER.info("Skipping entity {}".format(entity_identifier))
                        continue

                if entity.entity_type == EntityTypes.ADDRESS:
                    try:
                        siemplify.LOGGER.info("Fetching agent for address {}".format(entity_identifier))
                        agent = sentinel_one_manager.get_agent_by_ip(ip_address=entity_identifier)
                    except SentinelOneV2NotFoundError as e:
                        failed_entities.append(entity_identifier)
                        siemplify.LOGGER.info(e)
                        siemplify.LOGGER.info("Skipping entity {}".format(entity_identifier))
                        continue

                if agent and agent.uuid:
                    siemplify.LOGGER.info("Found agent {} for entity {}".format(agent.uuid, entity_identifier))
                    siemplify.LOGGER.info("Initiating full scan for agent {}".format(agent.uuid))
                    sentinel_one_manager.initiate_full_scan_by_uuid(agent.uuid)
                    successful_entities.append(entity_identifier)
                else:
                    siemplify.LOGGER.error('Error: Not found uuid for entity "{}"'.format(entity_identifier))
            except Exception as err:
                failed_entities.append(entity_identifier)
                errors_dict[entity_identifier] = str(err)
                siemplify.LOGGER.error("An error occurred on the {} entity: {}".format(entity_identifier, err))
                siemplify.LOGGER.exception(err)

        if errors_dict:
            siemplify.result.add_data_table(UNSUCCESSFUL_ATTEMPTS_TABLE_NAME, flat_dict_to_csv(errors_dict))

        if successful_entities:
            output_message = 'Successfully started the full disk scan on the following endpoints in {}: {}\n'\
                .format(PRODUCT_NAME, ", ".join(successful_entities))

            if failed_entities:
                output_message += "Action wasn't able to start a full disk scan on the following endpoints in {}: {}\n"\
                    .format(PRODUCT_NAME, ", ".join(failed_entities))

        else:
            output_message = 'No full disk scans were initiated.'
            result_value = False

    except Exception as err:
        output_message = "Error executing action '{}'. Reason: {}".format(INITIATE_FULL_SCAN_SCRIPT_NAME, err)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
