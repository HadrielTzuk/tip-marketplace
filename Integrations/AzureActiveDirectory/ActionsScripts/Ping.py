from SiemplifyAction import SiemplifyAction
from AzureADManager import AzureADManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, PING_SCRIPT_NAME
from TIPCommon import extract_configuration_param


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Directory ID',
                                         is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = "Connection Established."
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    try:
        AzureADManager(client_id=client_id, client_secret=client_secret, tenant=tenant, verify_ssl=verify_ssl,
                       force_check_connectivity=True)

        siemplify.LOGGER.info(f"Connection to Azure Active Directory established, performing action {INTEGRATION_NAME}")
    except Exception as e:
        output_message = f"An error occurred when trying to connect to the API: {e}"
        result_value = False
        siemplify.LOGGER.error(f"Connection to Azure Active Directory failed, performing action {INTEGRATION_NAME}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
