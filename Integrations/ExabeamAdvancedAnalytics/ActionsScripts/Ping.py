from TIPCommon import extract_configuration_param

from ExabeamAdvancedAnalyticsManager import ExabeamAdvancedAnalyticsManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, PING_SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # Integration configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root', is_mandatory=True,
                                           print_value=True)

    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token', is_mandatory=True,
                                            print_value=False)                                       

    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL', input_type=bool,
                                             is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = ExabeamAdvancedAnalyticsManager(api_root=api_root, api_token=api_token, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

        siemplify.LOGGER.info(f"Connecting to {INTEGRATION_DISPLAY_NAME}")
        manager.test_connectivity()
        output_message = f'Successfully connected to the {INTEGRATION_DISPLAY_NAME} server with the provided connection parameters!'

        result_value = True
        status = EXECUTION_STATE_COMPLETED

    except Exception as error:
        output_message = f'Failed to connect to the {INTEGRATION_DISPLAY_NAME} server! Error is {error}'
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
