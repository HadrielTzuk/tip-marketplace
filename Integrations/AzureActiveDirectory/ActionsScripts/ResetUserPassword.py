from SiemplifyAction import SiemplifyAction
from AzureADManager import AzureADManager
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from constants import INTEGRATION_NAME, RESET_USER_PASSWORD_SCRIPT_NAME
from TIPCommon import extract_configuration_param, extract_action_param
from utils import get_entity_original_identifier
from exceptions import AzurePasswordComplexityError

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RESET_USER_PASSWORD_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
 
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Directory ID',
                                         is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    new_password = extract_action_param(siemplify, param_name="Password", is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = True
    successful_entities, failed_entities, faild_password_entities = [], [], []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.USER]

    try:
        manager = AzureADManager(client_id=client_id, client_secret=client_secret, tenant=tenant, verify_ssl=verify_ssl,
                                 force_check_connectivity=True)
           
        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)

            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(
                    f"Timed out. execution deadline "
                    f"({convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)}) has passed")
                status = EXECUTION_STATE_TIMEDOUT
                break

            siemplify.LOGGER.info(f"Started processing entity: {entity_identifier}")

            try:
                manager.reset_user_password(entity_identifier, new_password)
                successful_entities.append(entity_identifier)
            except AzurePasswordComplexityError as e:
                faild_password_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity.identifier}. "
                                       f"The specified password does not comply with password complexity requirements.")
                siemplify.LOGGER.exception(e)
            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity.identifier}")
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info(f"Finished processing entity {entity_identifier}")
        if faild_password_entities:
            output_message = 'Failed to execute the action, the specified password does not comply with password ' \
                             'complexity requirements. Please provide a different password.'
            result_value = False
            status = EXECUTION_STATE_FAILED
        elif successful_entities:
            output_message += f"Password was changed for the following users: \n{', '.join(successful_entities)}\n"
                
            if failed_entities:
                output_message += f"Failed processing entities:\n{', '.join(failed_entities)}\n"
        else:
            output_message = "No user passwords were reset."
            result_value = False

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {RESET_USER_PASSWORD_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"An error occurred while running action: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
