from TIPCommon import extract_configuration_param, extract_action_param

from GSuiteManager import GSuiteManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_NAME,
    DELETE_GROUP_SCRIPT_NAME
)
from exceptions import GSuiteNotFoundException, GSuiteValidationException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, DELETE_GROUP_SCRIPT_NAME)
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
    email_address = extract_action_param(siemplify, param_name="Group Email Address", is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_FAILED
    result_value = False

    try:
        gsuite_manager = GSuiteManager(client_id=client_id, client_secret=client_secret, refresh_token=refresh_token,
                                       service_account_creds_path=service_account_json, delegated_email=delegated_email, verify_ssl=verify_ssl)
        try:
            gsuite_manager.delete_group(email_address)
            output_message = f"{INTEGRATION_NAME} group deleted."
            result_value = True
        except Exception as error:
            output_message = f"Action was not able to find {INTEGRATION_NAME} group for deletion."
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
