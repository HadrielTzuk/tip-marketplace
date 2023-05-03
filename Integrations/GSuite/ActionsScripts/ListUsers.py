from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

from GSuiteManager import GSuiteManager
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_NAME,
    LIST_USERS_SCRIPT_NAME,
    DEFAULT_MAX_USERS_TO_RETURN
)
from exceptions import GSuiteValidationException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, LIST_USERS_SCRIPT_NAME)
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
    customer_id = extract_action_param(siemplify, param_name="Customer ID", is_mandatory=False, print_value=True)
    domain = extract_action_param(siemplify, param_name="Domain", is_mandatory=False, print_value=True)
    manager_email = extract_action_param(siemplify, param_name="Manager Email", is_mandatory=False, print_value=True)
    only_admin_accounts = extract_action_param(siemplify, param_name="Return only Admin Accounts?", is_mandatory=False, input_type=bool,
                                               default_value=False, print_value=True)
    only_delegated_admin_accounts = extract_action_param(siemplify, param_name="Return only Delegated Admin Accounts?", is_mandatory=False,
                                                         input_type=bool, default_value=False, print_value=True)
    only_suspended_accounts = extract_action_param(siemplify, param_name="Return only Suspended Users?", is_mandatory=False,
                                                   input_type=bool, default_value=False, print_value=True)
    org_unit_path = extract_action_param(siemplify, param_name="Org Unit Path", is_mandatory=False, print_value=True)
    department = extract_action_param(siemplify, param_name="Department", is_mandatory=False, print_value=True)
    max_results = extract_action_param(siemplify, param_name="Record Limit", is_mandatory=False, input_type=int,
                                       default_value=DEFAULT_MAX_USERS_TO_RETURN, print_value=True)
    custom_query = extract_action_param(siemplify, param_name="Custom Query Parameter", is_mandatory=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_FAILED
    result_value = False

    try:
        gsuite_manager = GSuiteManager(client_id=client_id, client_secret=client_secret, refresh_token=refresh_token,
                                       service_account_creds_path=service_account_json, delegated_email=delegated_email, verify_ssl=verify_ssl)
        try:
            users = gsuite_manager.list_users(
                customer_id=customer_id,
                limit=max_results,
                domain=domain,
                manager_email=manager_email,
                only_admin_accounts=only_admin_accounts,
                only_delegated_admin_accounts=only_delegated_admin_accounts,
                only_suspended_users=only_suspended_accounts,
                org_unit_path=org_unit_path,
                department=department,
                custome_query=custom_query,
            )
            if users:
                siemplify.result.add_result_json([user.as_json() for user in users])
                siemplify.result.add_data_table("Google Gsuite Users", construct_csv([user.as_csv() for user in users]))
                output_message = f"Action successfully returned {INTEGRATION_NAME} Directory user list"
                result_value = True
            else:
                output_message = f"No users were returned."
        except Exception as error:
            output_message = f"Error executing action {LIST_USERS_SCRIPT_NAME}. Reason: " \
                             f"{'Invalid parameters were provided' if isinstance(error, GSuiteValidationException) else f'{error}'}"
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(error)

        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        output_message = f"Failed to connect to Google {INTEGRATION_NAME}! Error is: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
