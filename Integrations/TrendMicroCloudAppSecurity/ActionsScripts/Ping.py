from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TrendMicroCloudAppSecurityManager import TrendMicroCloudAppSecurityManager
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    PING_ACTION,
    DISPLAY_INTEGRATION_NAME
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root", is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Key", is_mandatory=True, print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""
    
    try:
        trend_manager = TrendMicroCloudAppSecurityManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl)
        trend_manager.test_connectivity()
        output_message += "Successfully connected to the {} instance with the provided connection parameters!".format(DISPLAY_INTEGRATION_NAME)
        
    except Exception as e:
        output_message += 'Failed to connect to the {}! Error: {}.'.format(DISPLAY_INTEGRATION_NAME, e)
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
