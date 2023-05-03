from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, GENERATE_TOKEN_SCRIPT_NAME
from ExchangeManager import ExchangeManager
from urllib.parse import urlparse, parse_qs


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GENERATE_TOKEN_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(
        siemplify=siemplify,
        param_name='Client ID',
        is_mandatory=False,
        provider_name=INTEGRATION_NAME)

    client_secret = extract_configuration_param(
        siemplify=siemplify,
        param_name='Client Secret',
        is_mandatory=False,
        provider_name=INTEGRATION_NAME)

    tenant_id = extract_configuration_param(
        siemplify=siemplify,
        param_name='Tenant (Directory) ID',
        is_mandatory=False,
        provider_name=INTEGRATION_NAME)

    redirect_url = extract_configuration_param(
        siemplify=siemplify,
        param_name='Redirect URL',
        is_mandatory=False,
        provider_name=INTEGRATION_NAME)

    auth_url = extract_action_param(
        siemplify,
        param_name="Authorization URL",
        is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = False
    status = EXECUTION_STATE_COMPLETED

    try:
        # Get the code from the url
        parsed_url = urlparse(auth_url)
        query = parse_qs(parsed_url.query)

        if query.get('code') and isinstance(query.get('code'), list):
            code = query.get('code')[0]
            refresh_token = ExchangeManager.get_access_token_behalf_user(code, client_id, client_secret, tenant_id,
                                                                         redirect_url, siemplify.LOGGER)
            output_message = "Successfully fetched the refresh token: \n{}\nCopy this access token to the Integration " \
                             "Configuration.\nNote: This Token is valid for 90 days only".format(refresh_token)
            result = True
        else:
            output_message = "Incorrect URL. Parameter \"code\" was not found. Please check, if you copied the URL " \
                             "properly."
    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Failed to get the refresh token! Error is {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Status: {}".format(status))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
