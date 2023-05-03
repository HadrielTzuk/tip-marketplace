import urllib.parse as urlparse
from urllib.parse import parse_qs

from TIPCommon import extract_configuration_param, extract_action_param

from GSuiteManager import GSuiteManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_NAME,
    GENERATE_TOKEN_SCRIPT_NAME
)
from exceptions import GSuiteValidationException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, GENERATE_TOKEN_SCRIPT_NAME)
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INTEGRATION Configuration
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                            param_name="Client ID")
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Client Secret")

    # Action configuration
    redirect_url = extract_action_param(siemplify, param_name="Redirect URL", is_mandatory=True, print_value=True)
    authorization_url = extract_action_param(siemplify, param_name="Authorization URL", is_mandatory=True, print_value=True)
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        try:
            # Parse 'code' GET param from authorization URL
            parsed_auth_link = urlparse.urlparse(authorization_url)
            siemplify.LOGGER.info(f"Parsed auth link {parsed_auth_link}")
            code = parse_qs(parsed_auth_link.query).get('code', '')[0]
        except Exception:
            raise GSuiteValidationException("Failed to parse Authorization URL")

        token = GSuiteManager.obtain_access_token(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_url,
            code=code
        )
        output_message = f"Successfully get an access token.\n{token.access_token}\nCopy this access token to the Integration " \
                         "Configuration.\nNote: This Token is valid for 90 days only"
        status = EXECUTION_STATE_COMPLETED
        result_value = True
    except Exception as error:
        output_message = f'Error executing action {GENERATE_TOKEN_SCRIPT_NAME}. Reason: {error}'
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
