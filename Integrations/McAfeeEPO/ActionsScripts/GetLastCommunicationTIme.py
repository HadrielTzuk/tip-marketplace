from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from McAfeeManager import McafeeEpoManager
from McAfeeCommon import McAfeeCommon
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, GET_LAST_COMMUNICATION_TIME_SCRIPT_NAME, \
    GET_LAST_COMMUNICATION_TIME_TABLE_NAME, PRODUCT_NAME
from utils import get_entity_original_identifier

SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_LAST_COMMUNICATION_TIME_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='ServerAddress',
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                           is_mandatory=True)
    group_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='GroupName')
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name='CA Certificate File - parsed into Base64 String')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    # CSV Headers
    csv_output = []
    json_results = {}
    result_value = True
    successful_entities, failed_entities, systems_data = [], [], []
    status = EXECUTION_STATE_COMPLETED
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = McafeeEpoManager(api_root=api_root, username=username, password=password, group_name=group_name,
                                   ca_certificate=ca_certificate, verify_ssl=verify_ssl,
                                   force_check_connectivity=True)
        if manager.group and suitable_entities:
            systems_data = manager.get_systems(manager.group.group_id)

        for entity in suitable_entities:
            siemplify.LOGGER.info(f'Started processing entity: {entity}')
            entity_original_identifier = get_entity_original_identifier(entity)
            try:
                if manager.group:
                    McAfeeCommon.filter_systems_by_entity(systems_data, entity)

                last_communication_time = manager.get_last_comm_time(entity_original_identifier)
                json_results[entity.identifier] = last_communication_time.to_json()
                csv_output.append(last_communication_time.to_csv(entity_original_identifier))
                successful_entities.append(entity_original_identifier)
                siemplify.LOGGER.info(f'Finished processing entity: {entity}')
            except Exception as e:
                failed_entities.append(entity_original_identifier)
                siemplify.LOGGER.error(f'An error occurred on entity {entity_original_identifier}')
                siemplify.LOGGER.exception(e)

        if successful_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            siemplify.result.add_data_table(GET_LAST_COMMUNICATION_TIME_TABLE_NAME, construct_csv(csv_output))
            output_message = 'Successfully retrieved last communication time information from the ' \
                             f'following endpoints in {PRODUCT_NAME}: {", ".join(successful_entities)}\n'
            if failed_entities:
                output_message += 'Action wasn\'t able to retrieve last communication time information from the ' \
                                  f'following endpoints in {PRODUCT_NAME}: {", ".join(failed_entities)}\n'
        else:
            result_value = False
            output_message = 'No information about last communication time was found on the provided endpoints.'

    except Exception as e:
        output_message = f'Error executing action "{GET_LAST_COMMUNICATION_TIME_SCRIPT_NAME}". Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
