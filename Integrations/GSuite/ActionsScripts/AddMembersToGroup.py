from TIPCommon import extract_configuration_param, extract_action_param

from GSuiteManager import GSuiteManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_NAME,
    ADD_MEMBERS_TO_GROUP_SCRIPT_NAME
)
from exceptions import GSuiteEntityExistsException

SUPPORTED_ENTITIES = [EntityTypes.USER]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, ADD_MEMBERS_TO_GROUP_SCRIPT_NAME)
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INTEGRATION Configuration
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                            param_name="Client ID", is_mandatory=False, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Client Secret", is_mandatory=False, print_value=False)
    refresh_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Refresh Token", is_mandatory=False, print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, print_value=True, is_mandatory=True)
    service_account_json = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                       param_name='Service Account JSON', is_mandatory=False,
                                                       print_value=False)

    delegated_email = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Delegated Email',
                                                  is_mandatory=False, print_value=True)

    # Action configuration
    group_email_address = extract_action_param(siemplify, param_name="Group Email Address", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True

    successful_entities = []
    failed_entities = []
    existing_entities = []

    json_results = []
    try:
        gsuite_manager = GSuiteManager(client_id=client_id, client_secret=client_secret, refresh_token=refresh_token,
                                       service_account_creds_path=service_account_json, delegated_email=delegated_email, verify_ssl=verify_ssl)
        for entity in siemplify.target_entities:
            if entity.entity_type not in SUPPORTED_ENTITIES:
                siemplify.LOGGER.info("Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                continue
            siemplify.LOGGER.info(f"Adding member {entity.identifier.strip()} to group")
            try:
                member = gsuite_manager.add_member_to_group(
                    group_email_address=group_email_address,
                    primary_email_address=entity.identifier.strip()
                )
                json_results.append(member.as_json())
                successful_entities.append(entity.identifier)
                siemplify.LOGGER.info(f"Member {entity.identifier.strip()} was successfully added to group")
            except GSuiteEntityExistsException as error:
                existing_entities.append(entity.identifier)
                siemplify.LOGGER.error(f"Member {entity.identifier} already exists in group")
                siemplify.LOGGER.exception(error)

            except Exception as error:
                siemplify.LOGGER.error(f"Failed to add member {entity.identifier} to group")
                siemplify.LOGGER.exception(error)
                failed_entities.append(entity.identifier)

        if successful_entities:
            siemplify.result.add_result_json(json_results)
            output_message = 'The following entities were added to the group:\n   {}\n\n'.format("\n   ".join(successful_entities))
        else:
            output_message = "No entities were added to the group.\n\n"

        if existing_entities:
            output_message += "The following members already exist in group:\n   {}\n\n".format("\n   ".join(existing_entities))

        if failed_entities:
            output_message += "Action failed to add the following members to group:\n   {}".format("\n   ".join(failed_entities))

    except Exception as error:
        output_message = f'Error executing action {ADD_MEMBERS_TO_GROUP_SCRIPT_NAME}. Reason: {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
