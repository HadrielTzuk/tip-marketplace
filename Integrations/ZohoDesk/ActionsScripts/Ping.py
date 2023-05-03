from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from ZohoDeskManager import ZohoDeskManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True, remove_whitespaces=False)
    refresh_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Refresh Token",
                                                is_mandatory=False, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = ZohoDeskManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                  refresh_token=refresh_token, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        manager.test_connectivity()
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully connected to the {INTEGRATION_DISPLAY_NAME} server with the provided " \
                         f"connection parameters!"

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {PING_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Failed to connect to the {INTEGRATION_DISPLAY_NAME} server! Error is {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
