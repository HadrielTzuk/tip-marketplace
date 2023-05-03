import json

from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from GSuiteManager import GSuiteManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_NAME,
    LIST_GROUP_MEMBERS_SCRIPT_NAME
)
from exceptions import GSuiteNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, LIST_GROUP_MEMBERS_SCRIPT_NAME)
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
    include_derived_membership = extract_action_param(siemplify, param_name="Include Derived Membership", is_mandatory=True,
                                                      default_value=True, print_value=True, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_FAILED
    result_value = json.dumps([])

    try:
        gsuite_manager = GSuiteManager(client_id=client_id, client_secret=client_secret, refresh_token=refresh_token,
                                       service_account_creds_path=service_account_json, delegated_email=delegated_email, verify_ssl=verify_ssl)
        group_members = gsuite_manager.list_group_members(
            group_email_address=group_email_address,
            include_derived_membership=include_derived_membership
        )
        json_results = [member.as_json() for member in group_members]
        siemplify.result.add_result_json(json_results)
        siemplify.result.add_data_table(f"Group {group_email_address} Members",
                                        construct_csv([member.as_csv() for member in group_members]))
        output_message = f"Successfully fetched group members."

        status = EXECUTION_STATE_COMPLETED
        result_value = json.dumps(json_results)

    except Exception as error:
        output_message = f"Error executing action {LIST_GROUP_MEMBERS_SCRIPT_NAME}. Reason: " \
                         f"{'Group email address was not found' if isinstance(error, GSuiteNotFoundException) else f'{error}'}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
