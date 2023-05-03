from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from MicrosoftGraphSecurityManager import MicrosoftGraphSecurityManager
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = "MicrosoftGraphSecurity"
SCRIPT_NAME = "Ping"


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
                                                       param_name="Certificate Password", is_mandatory=False, input_type=str)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant",
                                         is_mandatory=True, input_type=str)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        siemplify.LOGGER.info("Connecting to Microsoft Graph Security.")
        mtm = MicrosoftGraphSecurityManager(client_id, secret_id, certificate_path, certificate_password, tenant)
        siemplify.LOGGER.info("Connected successfully.")

        output_message = "Connection Established"
        result_value = 'true'
        status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        siemplify.LOGGER.error(f"Some errors occurred. Error: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Some errors occurred. Error: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
