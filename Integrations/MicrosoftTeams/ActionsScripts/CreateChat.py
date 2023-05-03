from MicrosoftManager import MicrosoftTeamsManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftConstants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, CREATE_CHAT_ACTION
from SiemplifyDataModel import EntityTypes


SUPPORTED_ENTITY_TYPES = [EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_CHAT_ACTION
    siemplify.LOGGER.info(f"----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    secret_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret ID",
                                            is_mandatory=True, print_value=False)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant",
                                         is_mandatory=True, print_value=True)
    token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Refresh Token",
                                        is_mandatory=True, print_value=False)
    redirect_url = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Redirect URL",
                                               is_mandatory=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    json_results = {}
    successful_entities = []
    failed_entities = []
    not_found_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        manager = MicrosoftTeamsManager(client_id=client_id, client_secret=secret_id, tenant=tenant,
                                        refresh_token=token, redirect_url=redirect_url)

        users = {}

        for item in manager.list_users():
            users[item.get("displayName")] = item.get("id")
            users[item.get("mail")] = item.get("id")

        me = manager.check_account()

        for entity in suitable_entities:
            siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))

            if entity.identifier in users.keys():
                try:
                    chat = manager.create_chat([me.user_id, users.get(entity.identifier)])
                    json_results[entity.identifier] = chat.to_json()
                    successful_entities.append(entity)
                except Exception as e:
                    siemplify.LOGGER.error(f"Failed processing entities: {entity.identifier}: Error is: {e}")
                    failed_entities.append(entity)
            else:
                siemplify.LOGGER.info(f"User not found: {entity.identifier}")
                not_found_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}\n".format(entity.identifier))

        if successful_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message = "Successfully created chat with the following users in {}: \n{}"\
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in successful_entities]))

        if not_found_entities:
            output_message += "\nThe following users were not found in {}: \n{}"\
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in not_found_entities]))

        if failed_entities:
            output_message += "\nAction wasn't able to create a chat with the following users in {}: \n{}."\
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in failed_entities]))

        if not successful_entities:
            result_value = False

            if len(not_found_entities) == len(suitable_entities):
                output_message = f"None of the provided users were found in {INTEGRATION_DISPLAY_NAME}."
            elif len(failed_entities) == len(suitable_entities):
                output_message = f"Action wasn't able to create a chat with the provided users in " \
                                 f"{INTEGRATION_DISPLAY_NAME}."

    except Exception as e:
        output_message = f"Error executing action {CREATE_CHAT_ACTION}. Reason: {e}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(f"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
