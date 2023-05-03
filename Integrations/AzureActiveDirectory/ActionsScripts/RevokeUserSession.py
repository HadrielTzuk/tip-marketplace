from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from AzureADManager import AzureADManager
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, REVOKE_USER_SESSION_SCRIPT_NAME, NAME_FILTER_KEYS, EMAIL_FILTER_KEYS
from utils import get_entity_original_identifier, is_valid_email
from exceptions import AzureADNotFoundError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REVOKE_USER_SESSION_SCRIPT_NAME
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

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = True
    json_results, successful_entities, failed_entities = {}, [], []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.USER]

    try:

        manager = AzureADManager(client_id=client_id, client_secret=client_secret, tenant=tenant, verify_ssl=verify_ssl,
                                 force_check_connectivity=True)

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)

            siemplify.LOGGER.info(f"Started processing entity: {entity_identifier}")
            filter_keys = EMAIL_FILTER_KEYS if is_valid_email(entity_identifier) else NAME_FILTER_KEYS

            try:
                siemplify.LOGGER.info(f"current filter keys - {filter_keys}")
                user_id = manager.get_user_id_with_filter(
                    user_identifier=entity_identifier,
                    filter_keys=filter_keys
                )
                response_json = manager.revoke_user_session(user_id=user_id)
                successful_entities.append(entity_identifier)
                json_results[entity_identifier] = response_json
            except AzureADNotFoundError as e:
                failed_entities.append(entity_identifier)
                json_results[entity_identifier] = {"error": "User not found"}
                siemplify.LOGGER.error(f"An error occurred on entity {entity_identifier}")
                siemplify.LOGGER.exception(e)
            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity_identifier}")
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info(f"Finished processing entity {entity_identifier}")

        if successful_entities:
            output_message += f"Successfully revoked sessions for the following users in Azure AD:\n" \
                              f"{', '.join(successful_entities)}\n\n"
                
            if failed_entities:
                output_message += f"Action wasn't able to find the following users in Azure AD: \n" \
                                  f"{', '.join(failed_entities)}\n\n"

        else:
            output_message = f"None of the provided users were found in Azure AD."
            result_value = False

        if json_results:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    except Exception as e:
        output_message = f"Error executing action {REVOKE_USER_SESSION_SCRIPT_NAME}. Reason: {e}"
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()

