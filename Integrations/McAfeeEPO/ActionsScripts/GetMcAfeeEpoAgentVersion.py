from McAfeeCommon import McAfeeCommon
from McAfeeManager import McafeeEpoManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import (
    convert_dict_to_json_result_dict,
    output_handler
)
from TIPCommon import extract_configuration_param
from constants import (
    GET_MCAFEE_EPO_AGENT_VERSION_SCRIPT_NAME,
    INTEGRATION_NAME,
    PRODUCT_NAME
)
from utils import get_entity_original_identifier

SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_MCAFEE_EPO_AGENT_VERSION_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

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

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    result_value = ''
    agent_version = None
    status = EXECUTION_STATE_COMPLETED
    success_entities, failed_entities, system_data, json_result = [], [], [], {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = McafeeEpoManager(api_root=api_root, username=username, password=password, group_name=group_name,
                                   ca_certificate=ca_certificate, verify_ssl=verify_ssl, force_check_connectivity=True)
        if suitable_entities:
            system_data = manager.get_systems_by_self_group()

        for entity in suitable_entities:
            siemplify.LOGGER.info(f"Started processing entity: {entity}")
            entity_original_identifier = get_entity_original_identifier(entity)
            try:
                agent_version = None

                if manager.group:
                    McAfeeCommon.filter_systems_by_entity(system_data, entity)

                system_info = manager.get_system_info(entity_original_identifier)

                if system_info:
                    agent_version = system_info.to_agent_version_json()
                    result_value = system_info.agent_version[-1] or 'null'

                if agent_version:
                    success_entities.append(entity_original_identifier)
                    json_result[entity_original_identifier] = agent_version
                else:
                    failed_entities.append(entity_original_identifier)

                siemplify.LOGGER.info(f"Finished processing entity {entity}")
            except Exception as e:
                failed_entities.append(entity_original_identifier)
                siemplify.LOGGER.error(e)
                siemplify.LOGGER.exception(e)

        if success_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
            output_message = 'Successfully retrieved agent version information from the following endpoints in ' \
                             f'{PRODUCT_NAME}: {", ".join(success_entities)}\n'
            if failed_entities:
                output_message += 'Action wasn\'t able to retrieve agent version information from the following ' \
                                  f'endpoints in {PRODUCT_NAME}: {", ".join(failed_entities)}\n'
        else:
            result_value = 0
            output_message = 'No information about agent version was found on the provided endpoints.'
    except Exception as e:
        output_message = f"Error executing action '{GET_MCAFEE_EPO_AGENT_VERSION_SCRIPT_NAME}'. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = 0

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()


