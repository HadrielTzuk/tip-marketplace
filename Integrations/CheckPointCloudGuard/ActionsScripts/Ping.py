from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from Dome9Manager import Dome9Manager
from TIPCommon import extract_configuration_param


INTEGRATION_NAME = u"CheckPointCloudGuard"
SCRIPT_NAME = u"Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_key_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Key ID",
                                          is_mandatory=True)
    api_key_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Key Secret",
                                         is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        dome_manager = Dome9Manager(api_key_id=api_key_id, api_key_secret=api_key_secret, verify_ssl=verify_ssl)
        dome_manager.test_connectivity()
        status = EXECUTION_STATE_COMPLETED
        output_message = "Successfully connected to the Check Point Cloud Guard server with the provided connection parameters!"
        result_value = "true"

    except Exception as e:
        siemplify.LOGGER.error("Failed to connect to the Check Point Cloud Guard server! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "Failed to connect to the Check Point Cloud Guard server! Error is {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u'__main__':
    main()
