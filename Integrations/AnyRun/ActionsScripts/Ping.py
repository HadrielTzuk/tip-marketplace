from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction, ScriptResult
from AnyRunManager import AnyRunManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    PING_ACTION
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Api Key")

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        anyrun_manager = AnyRunManager(api_key=api_key)
        anyrun_manager.test_connectivity()
        output_message = "Successfully connected to the {} service with the provided connection parameters.".format(INTEGRATION_NAME)

    except Exception as e:
        output_message = 'Failed to connect to the {} service! Error is {}. Reason: {}'.format(INTEGRATION_NAME, PING_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
