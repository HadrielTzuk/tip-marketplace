from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftGraphSecurityManager import MicrosoftGraphSecurityManager
from TIPCommon import extract_configuration_param, extract_action_param


INTEGRATION_NAME = "MicrosoftGraphSecurity"
SCRIPT_NAME = "Kill User Session"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, input_type=str)
    secret_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret ID",
                                            is_mandatory=False, input_type=str)
    certificate_path = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                   param_name="Certificate Path", is_mandatory=False, input_type=str)
    certificate_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                       param_name="Certificate Password", is_mandatory=False,
                                                       input_type=str)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant",
                                         is_mandatory=True, input_type=str)

    user_id = extract_action_param(siemplify, param_name='userPrincipalName | ID', input_type=str, is_mandatory=True,
                                    print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        siemplify.LOGGER.info("Connecting to Microsoft Graph Security.")
        microsoft_graph_manager = MicrosoftGraphSecurityManager(client_id, secret_id, certificate_path, certificate_password, tenant)
        siemplify.LOGGER.info("Connected successfully.")

        siemplify.LOGGER.info(f"Killing user {user_id} session")
        microsoft_graph_manager.kill_user_session(user_id)

        siemplify.LOGGER.info("User tokens invalidated. Kill User session was successful.")
        output_message = "User tokens invalidated. Kill User session was successful."
        status = EXECUTION_STATE_COMPLETED
        result_value = "true"

    except Exception as e:
        siemplify.LOGGER.error(f"Some errors occurred. Error: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Some errors occurred. Error: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()