from TIPCommon import extract_configuration_param, extract_action_param

from GSuiteManager import GSuiteManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_NAME,
    CREATE_USER_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, CREATE_USER_SCRIPT_NAME)
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
    given_name = extract_action_param(siemplify, param_name="Given Name", is_mandatory=True, print_value=True)
    family_name = extract_action_param(siemplify, param_name="Family Name", is_mandatory=True, print_value=True)
    password = extract_action_param(siemplify, param_name="Password", is_mandatory=True, print_value=False)
    primary_email = extract_action_param(siemplify, param_name="Email Address", is_mandatory=True, print_value=True)
    phone = extract_action_param(siemplify, param_name="Phone", is_mandatory=False, print_value=True)
    gender = extract_action_param(siemplify, param_name="Gender", is_mandatory=False, print_value=True)
    department = extract_action_param(siemplify, param_name="Department", is_mandatory=False, print_value=True)
    organization = extract_action_param(siemplify, param_name="Organization", is_mandatory=False, print_value=True)
    note = extract_action_param(siemplify, param_name="Note", is_mandatory=False, print_value=True)
    change_password_on_first_login = extract_action_param(siemplify, param_name="Change Password At Next Login", input_type=bool,
                                                          is_mandatory=True,
                                                          default_value=False,
                                                          print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        gsuite_manager = GSuiteManager(client_id=client_id, client_secret=client_secret, refresh_token=refresh_token,
                                       service_account_creds_path=service_account_json, delegated_email=delegated_email, verify_ssl=verify_ssl)
        user = gsuite_manager.create_user(
            given_name=given_name,
            family_name=family_name,
            password=password,
            primary_email=primary_email,
            change_password_at_next_login=change_password_on_first_login,
            phone=phone,
            organization=organization,
            department=department,
            gender=gender,
            note=note
        )
        siemplify.result.add_result_json(user.as_json())
        output_message = f"Successfully created user {given_name} {family_name} with primary email address {primary_email}"
    except Exception as error:
        output_message = f'Error executing action {CREATE_USER_SCRIPT_NAME}. Reason: {error}'
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
