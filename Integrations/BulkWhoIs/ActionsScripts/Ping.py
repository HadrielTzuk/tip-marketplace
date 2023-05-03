from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from WhoisManager import WhoisManager
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = u"BulkWhoIS"
SCRIPT_NAME = u"BulkWhoIS - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL", default_value=False, input_type=bool)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key", is_mandatory=True, input_type=unicode)
    api_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret Key", is_mandatory=True, input_type=unicode)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    try:
        whois = WhoisManager(api_key, api_secret, verify_ssl=verify_ssl)
        status = EXECUTION_STATE_COMPLETED
        is_connected = whois.test_connectivity()

        if is_connected:
            output_message = u"Connection Established"
            result_value = u"true"
            siemplify.LOGGER.info(u"Finished processing")
        else:
            output_message = u"Connection Failed"
            result_value = u"false"
            status = EXECUTION_STATE_FAILED
    except Exception, e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Some errors occurred. Please check log"

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
