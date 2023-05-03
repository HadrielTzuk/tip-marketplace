from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from MicrosoftManager import MicrosoftTeamsManager, URL_AUTHORIZATION
from TIPCommon import extract_configuration_param,extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftConstants import (
    INTEGRATION_NAME,
    GET_AUTHORIZATION_ACTION
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_AUTHORIZATION_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client ID", is_mandatory=True, print_value=True)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Tenant", is_mandatory=True, print_value=True)
    redirect_url = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Redirect URL", is_mandatory=False, print_value=True)    

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""

    try:
        url = URL_AUTHORIZATION.format(tenant=tenant, client_id=client_id, redirect_uri=redirect_url)
        siemplify.result.add_link("Browse to this authorization link", url)
        output_message = "Your browser should be redirected with a code in the address bar. In order to complete the registration, run 'Generate Token' action with the received url in the address bar." if url else "Failed to create an authorization url"
        if url:
            result_value = True
    except Exception as e:
        output_message = f'Error executing action {GET_AUTHORIZATION_ACTION}. Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        f"\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
    main()