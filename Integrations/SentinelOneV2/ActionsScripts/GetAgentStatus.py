from SiemplifyAction import SiemplifyAction
from exceptions import SentinelOneV2NotFoundError
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, flat_dict_to_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import GET_AGENT_STATUS_SCRIPT_NAME, INTEGRATION_NAME, ACTIVE_STATUS_VALUE, NOT_ACTIVE_STATUS_VALUE, \
    UNSUCCESSFUL_ATTEMPTS_TABLE_NAME, AGENT_STATUSES_TABLE_NAME
from utils import get_entity_original_identifier
from SentinelOneV2Factory import SentinelOneV2ManagerFactory

SPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_AGENT_STATUS_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SPORTED_ENTITY_TYPES]

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ''
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    json_statuses, errors_dict, table_statuses = {}, {}, {}
    successful_entities, failed_entities = [], []

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
                    siemplify.LOGGER.info("Fetching agent {} status".format(agent.uuid))
                    agent_status = ACTIVE_STATUS_VALUE if sentinel_one_manager.get_agent_status(agent.uuid) \
                        else NOT_ACTIVE_STATUS_VALUE
                    json_statuses[entity_identifier] = {
                        "status": agent_status
                    }
                    table_statuses[entity_identifier] = agent_status
                    successful_entities.append(entity_identifier)
                    siemplify.LOGGER.info("Agent: {} - status: {}".format(agent.uuid, json_statuses[entity_identifier]))
                else:
                    failed_entities.append(entity_identifier)
                    siemplify.LOGGER.error('Error: Not found uuid for entity "{0}"'.format(entity_identifier))

            except Exception as err:
                errors_dict[entity_identifier] = str(err)
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error("An error occurred on the {} entity: {}".format(entity_identifier, err))
                siemplify.LOGGER.exception(err)

        if successful_entities:
            output_message = "Successfully retrieved information about agent status for the following endpoints:\n{}\n"\
                .format(", ".join(successful_entities))
            siemplify.result.add_data_table(AGENT_STATUSES_TABLE_NAME, flat_dict_to_csv(table_statuses))
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_statuses))

        if failed_entities:
            output_message += "Action wasn't able to retrieve information about agent status for the following " \
                              "endpoints:\n{}\n".format(", ".join(failed_entities))

        if not successful_entities:
            output_message = "No information about agent status was found for the provided endpoints."
            result_value = False

        if errors_dict:
            siemplify.result.add_data_table(UNSUCCESSFUL_ATTEMPTS_TABLE_NAME, flat_dict_to_csv(errors_dict))

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(GET_AGENT_STATUS_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()

