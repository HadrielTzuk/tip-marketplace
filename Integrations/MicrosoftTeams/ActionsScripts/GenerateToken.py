from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from MicrosoftManager import MicrosoftTeamsManager
from urllib.parse import urlparse, parse_qs
from TIPCommon import extract_configuration_param,extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MicrosoftConstants import (
    INTEGRATION_NAME,
    GENERATE_TOKEN_ACTION
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GENERATE_TOKEN_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client ID", is_mandatory=True, print_value=True)
    secret_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Secret ID", is_mandatory=True, print_value=False)
    tenant = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Tenant", is_mandatory=True, print_value=True)
    redirect_url = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Redirect URL", is_mandatory=False, print_value=True)    

    url = extract_action_param(siemplify, param_name="Authorization URL", print_value=True, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    
    try:
        # Get the code from the url
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        result_value = 'false'
        if query.get('code') and isinstance(query.get('code'), list):
            code = query.get('code')[0]
            refresh_token = MicrosoftTeamsManager.get_access_token_behalf_user(code, client_id, secret_id, tenant, redirect_url)
            output_message = "Successfully get an access token.\n{}\nCopy this access token to the Integration " \
                            "Configuration.\nNote: This Token is valid for 90 days only".format(refresh_token) if \
                refresh_token else "Failed to get an access token"
            result_value = 'true' if refresh_token else 'false'
        else:
            output_message = "Incorrect URL. Parameter \"code\" was not found. Please check, " \
                            "if you copied the URL properly."

    except Exception as e:
        output_message = f'Error executing action {GENERATE_TOKEN_ACTION}. Reason: {e}'
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



