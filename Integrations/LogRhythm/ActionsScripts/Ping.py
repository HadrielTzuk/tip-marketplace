from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from constants import INTEGRATION_NAME, PING_SCRIPT_NAME
from TIPCommon import extract_configuration_param
from LogRhythmManager import LogRhythmRESTManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f"Successfully connected to the {INTEGRATION_NAME} server with the provided connection parameters!"
    try:
        LogRhythmRESTManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl, force_check_connectivity=True)

    except Exception as e:
        output_message = f"Failed to connect to the {INTEGRATION_NAME} server! Error is {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
