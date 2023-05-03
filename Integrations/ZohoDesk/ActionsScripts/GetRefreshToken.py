from TIPCommon import extract_configuration_param, extract_action_param
from ZohoDeskManager import ZohoDeskManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, GET_REFRESH_TOKEN_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_REFRESH_TOKEN_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INTEGRATION Configuration
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    # Action configuration
    authorization_link = extract_action_param(siemplify, param_name="Authorization Link", is_mandatory=True,
                                              print_value=True)
    authorization_code = extract_action_param(siemplify, param_name="Authorization Code", is_mandatory=True,
                                              remove_whitespaces=False)
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        refresh_token = ZohoDeskManager.obtain_refresh_token(
            client_id=client_id,
            client_secret=client_secret,
            code=authorization_code,
            auth_link=authorization_link,
            verify_ssl=verify_ssl
        )
        siemplify.result.add_result_json({"refresh_token": refresh_token})
        output_message = f"Successfully generated refresh token. " \
                         f"Copy the value into \"Refresh Token\" parameter in the integration configuration."
        status = EXECUTION_STATE_COMPLETED
        result_value = True
    except Exception as error:
        output_message = f'Error executing action {GET_REFRESH_TOKEN_SCRIPT_NAME}. Reason: {error}'
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
