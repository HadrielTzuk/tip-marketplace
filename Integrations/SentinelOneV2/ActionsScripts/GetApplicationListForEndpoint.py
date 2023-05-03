from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, flat_dict_to_csv, dict_to_flat
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import (
    INTEGRATION_NAME,
    GET_APPLICATION_LIST_FOR_ENDPOINT_SCRIPT_NAME,
    UNSUCCESSFUL_ATTEMPTS_TABLE_NAME,
)
from exceptions import SentinelOneV2NotFoundError
from utils import get_entity_original_identifier
from SentinelOneV2Factory import SentinelOneV2ManagerFactory


SUITABLE_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_APPLICATION_LIST_FOR_ENDPOINT_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)
    max_items_to_return = extract_action_param(siemplify, param_name='Max Applications To Return', input_type=int,
                                               print_value=True)
    scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUITABLE_ENTITY_TYPES]

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ''
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_entities, failed_entities = [], []
    json_results, errors_dict = {}, {}

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

                if agent and agent.id:
                    siemplify.LOGGER.info("Found agent {} for entity {}".format(agent.id, entity_identifier))
                    siemplify.LOGGER.info("Fetching applications for agent {}".format(agent.id))
                    applications_list = sentinel_one_manager.get_applications_from_endpoint(agent_id=agent.id,
                                                                                            limit=max_items_to_return)

                    if applications_list:
                        siemplify.LOGGER.info("Found {} applications".format(len(applications_list)))
                        successful_entities.append(entity_identifier)
                        siemplify.result.add_entity_table(entity_identifier,
                                                          construct_csv([app.to_csv() for app in applications_list]))
                        json_results[entity_identifier] = [app.to_json() for app in applications_list]
                    else:
                        failed_entities.append(entity_identifier)
                else:
                    siemplify.LOGGER.error('Error: Not found agent id for entity "{}"'.format(entity_identifier))
            except Exception as err:
                failed_entities.append(entity_identifier)
                errors_dict[entity_identifier] = str(err)
                siemplify.LOGGER.error("An error occurred on the {} entity: {}".format(entity_identifier, err))
                siemplify.LOGGER.exception(err)

        if successful_entities:
            output_message = 'Successfully retrieved available applications for the following endpoints:\n{}\n'\
                .format(", ".join(successful_entities))
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

        if failed_entities:
            output_message += "Action wasn't able to retrieve available applications for the following endpoints:\n{}\n"\
                .format(", ".join(failed_entities))

        if not successful_entities:
            output_message = 'No applications were retrieved for the provided endpoints.'
            result_value = False

        if errors_dict:
            siemplify.result.add_data_table(UNSUCCESSFUL_ATTEMPTS_TABLE_NAME, flat_dict_to_csv(errors_dict))

    except Exception as err:
        output_message = "Error executing action '{}'. Reason: {}"\
            .format(GET_APPLICATION_LIST_FOR_ENDPOINT_SCRIPT_NAME, err)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
