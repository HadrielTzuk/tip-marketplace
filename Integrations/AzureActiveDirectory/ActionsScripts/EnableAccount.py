from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from AzureADManager import AzureADManager
from SiemplifyDataModel import EntityTypes
from constants import INTEGRATION_NAME, ENABLE_ACCOUNT_SCRIPT_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime
from TIPCommon import extract_configuration_param
from utils import get_entity_original_identifier

SUPPORTED_ENTITY_TYPES = [EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENABLE_ACCOUNT_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Directory ID',
                                         is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    status = EXECUTION_STATE_COMPLETED
    result_value = False
    successful_entities, failed_entities = [], []
    try:
        manager = AzureADManager(client_id=client_id, client_secret=client_secret, tenant=tenant, verify_ssl=verify_ssl,
                                 force_check_connectivity=True)

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(f"Timed out. execution deadline "
                                       f"({convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)}) "
                                       f"has passed")
                status = EXECUTION_STATE_TIMEDOUT
                break

            siemplify.LOGGER.info(f"Started processing entity: {entity_identifier}")
            try:
                manager.enable_user(entity_identifier)
                successful_entities.append(entity_identifier)
                result_value = True
                siemplify.LOGGER.info(f"Finished processing entity {entity_identifier}")

            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity_identifier}")
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = f"Successfully enabled users: \n{', '.join(successful_entities)}\n"

            if failed_entities:
                output_message += f"Failed processing entities:\n{', '.join(failed_entities)}\n"

        else:
            output_message = "No users were enabled."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {ENABLE_ACCOUNT_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = f"An error occurred while running action: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
