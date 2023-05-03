from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from DigitalShadowsManager import DigitalShadowsManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = u"DigitalShadows"
SCRIPT_NAME = u"DigitalShadows - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          input_type=unicode)

    api_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Secret",
                                             input_type=unicode)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        # If no exception occur - then connection is successful
        manager = DigitalShadowsManager(api_key, api_secret)
        output_message = u"Connection Established"
        status = EXECUTION_STATE_COMPLETED
        result_value = u"true"

    except Exception, e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Error executing action 'Ping action'. Reason: {0}".format(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
