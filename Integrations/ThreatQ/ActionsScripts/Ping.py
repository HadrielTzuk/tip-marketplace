from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from ThreatQManager import ThreatQManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = u"ThreatQ"
SCRIPT_NAME = u"ThreatQ - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="ServerAddress",
                                           input_type=unicode)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="ClientId",
                                          input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                          input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           input_type=unicode)
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        # If no exception occur - then connection is successful
        threatq_manager = ThreatQManager(server_address, client_id, username, password)
        output_message = u"Connection Established."
        status = EXECUTION_STATE_COMPLETED
        result_value = u"true"
        siemplify.LOGGER.info(u"Finished processing")
    except Exception, e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        output_message = u"Connection Failed."
        status = EXECUTION_STATE_FAILED
        result_value = u"false"

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
