from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from AzureADIdentityProtectionManager import AzureADIdentityProtectionManager
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, UPDATE_USER_STATE_SCRIPT_NAME, PRINCIPAL_NAME, \
    DISPLAY_NAME, COMPROMISED_STATE
from UtilsManager import get_entity_original_identifier, is_valid_email


SUPPORTED_ENTITY_TYPES = [EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_USER_STATE_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True)
    tenant_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant ID",
                                            is_mandatory=True, print_value=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    user_state = extract_action_param(siemplify, param_name="State", print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities, failed_entities = [], []
    result_value = True
    suitable_entities = [entity for entity in siemplify.target_entities if
                         entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = AzureADIdentityProtectionManager(
            api_root=api_root,
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            verify_ssl=verify_ssl
        )
        manager.test_connectivity()

        for entity in suitable_entities:
            siemplify.LOGGER.info(f"Started processing entity: {entity.identifier}")

            try:
                filter_key = PRINCIPAL_NAME if is_valid_email(get_entity_original_identifier(entity)) else DISPLAY_NAME
                user = manager.get_user(username=entity.identifier, filter_key=filter_key)

                if user:
                    manager.update_user_state(
                        user_id=user.id,
                        compromise=True if user_state == COMPROMISED_STATE else False
                    )
                    successful_entities.append(entity)
                else:
                    failed_entities.append(entity.identifier)

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(f"An error occurred on entity {entity.identifier}")
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info(f"Finished processing entity {entity.identifier}")

        if successful_entities:
            output_message = f'Successfully updated the state of the following users in ' \
                             f'{INTEGRATION_DISPLAY_NAME}: ' \
                             f'{", ".join([entity.identifier for entity in successful_entities])}\n'

            if failed_entities:
                output_message += f'The following users were not found in ' \
                                  f'{INTEGRATION_DISPLAY_NAME}: {", ".join(failed_entities)}\n'
        else:
            output_message = f"None of the provided users were found in {INTEGRATION_DISPLAY_NAME}."
            result_value = False

    except Exception as e:
        output_message = f'Error executing action "{UPDATE_USER_STATE_SCRIPT_NAME}". Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
