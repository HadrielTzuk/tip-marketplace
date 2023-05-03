from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from MicrosoftManager import MicrosoftTeamsManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from MicrosoftConstants import (
    INTEGRATION_NAME,
    PING_ACTION
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client ID", is_mandatory=True, print_value=True)
    secret_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Secret ID", is_mandatory=True, print_value=False)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Tenant", is_mandatory=True, print_value=True)
    token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Refresh Token", is_mandatory=True, print_value=False)
    redirect_url = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Redirect URL", is_mandatory=False, print_value=True)    

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    
    try:
        MicrosoftTeamsManager(client_id, secret_id, tenant, token, redirect_url)
        output_message += f"Successfully connected to the {INTEGRATION_NAME} instance with the provided connection parameters!"
        
    except Exception as e:
        output_message += f"Failed to connect to the {INTEGRATION_NAME}! Error is {e}."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        f"\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()

