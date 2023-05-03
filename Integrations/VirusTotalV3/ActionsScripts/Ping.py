from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = "Successfully connected to the {} server with the provided connection parameters!"\
        .format(PROVIDER_NAME)
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)
        manager.test_connectivity()

    except Exception as err:
        output_message = "Failed to connect to the {} server! Error is {}".format(PROVIDER_NAME, err)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
