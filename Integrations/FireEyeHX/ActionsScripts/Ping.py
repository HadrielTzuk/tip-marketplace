from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from FireEyeHXManager import FireEyeHXManager
from TIPCommon import extract_configuration_param


INTEGRATION_NAME = u"FireEyeHX"
SCRIPT_NAME = u"Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                          is_mandatory=True, input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                         is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        hx_manager = FireEyeHXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)
        hx_manager.logout()
        status = EXECUTION_STATE_COMPLETED
        output_message = u"Successfully connected to the FireEye HX server with the provided connection parameters!"
        result_value = u"true"

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to connect to the FireEye HX server! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to connect to the FireEye HX server! Error is {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u'__main__':
    main()
