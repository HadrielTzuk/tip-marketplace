from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param
from UrlScanManager import UrlScanManager
from constants import INTEGRATION_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    # INIT INTEGRATION CONFIGURATIONS:
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = "Connection Established"
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        UrlScanManager(api_key=api_key, verify_ssl=verify_ssl, logger=siemplify.LOGGER, force_check_connectivity=True)
    except Exception as err:
        output_message = 'Connection Failed. Reason: {}'.format(err)
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
