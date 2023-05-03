from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED
from SiemplifyAction import SiemplifyAction
from AutoFocusManager import AutoFocusManager
from TIPCommon import extract_configuration_param


INTEGRATION_NAME = u'AutoFocus'
SCRIPT_NAME = u'HuntIp'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Api Key",
                                          is_mandatory=True, input_type=unicode)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        autofocus_manager = AutoFocusManager(api_key)
        autofocus_manager.test_connectivity()

        # If no exception occur - then connection is successful
        siemplify.LOGGER.info(u"Connected successfully.")
        output_message = u"Connected successfully."
        result_value = u"true"
        status = EXECUTION_STATE_COMPLETED

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u'__main__':
    main()
