from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction, ScriptResult
from RSAManager import RSAManager
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

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root")
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Username")
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        rsa_manager = RSAManager(api_root=api_root, username=username,
                                 password=password, verify_ssl=verify_ssl)
        rsa_manager.test_connectivity()
        output_message = "Connection Established."

    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(PING_ACTION, e)
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
