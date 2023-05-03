from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, GET_AUTHORIZATION_SCRIPT_NAME
from ExchangeManager import URL_AUTHORIZATION


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_AUTHORIZATION_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    client_id = extract_configuration_param(
        siemplify=siemplify,
        param_name='Client ID',
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

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        url = URL_AUTHORIZATION.format(tenant=tenant_id, client_id=client_id, redirect_uri=redirect_url)
        output_message = "Authorization URL generated successfully. Please navigate to the link below as the user " \
                         "that you want to run integration with, to get a URL with access code. The URL with access " \
                         "code should be provided next in the Generate Token action."
        siemplify.result.add_link("Browse to this authorization link", url)

    except Exception as e:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Failed to generate authorization URL! Error is {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Status: {}".format(status))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
