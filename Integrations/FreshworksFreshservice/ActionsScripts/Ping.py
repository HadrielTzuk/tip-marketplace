from TIPCommon import extract_configuration_param

from FreshworksFreshserviceManager import FreshworksFreshserviceManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import (
    INTEGRATION_IDENTIFIER,
    INTEGRATION_DISPLAY_NAME,
    PING_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_IDENTIFIER} - {PING_SCRIPT_NAME}"
    siemplify.LOGGER.info("=================== Main - Param Init ===================")

    # Integration configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name="API Key",
                                          is_mandatory=True, print_value=False, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_IDENTIFIER, param_name='Verify SSL', input_type=bool,
                                             is_mandatory=True, default_value=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        FreshworksFreshserviceManager(
            api_root=api_root,
            api_key=api_key,
            verify_ssl=verify_ssl,
            force_test_connectivity=True,
            siemplify=siemplify
        )
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully connected to the {INTEGRATION_DISPLAY_NAME} instance with the provided connection parameters!"
        result_value = True

    except Exception as error:
        output_message = f"Failed to connect to the {INTEGRATION_DISPLAY_NAME} instance! Error is: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
