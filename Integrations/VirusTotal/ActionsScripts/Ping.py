from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param
from VirusTotal import VirusTotalManager, VirusTotalInvalidAPIKeyManagerError

IDENTIFIER = u'VirusTotal'
SCRIPT_NAME = u"VirusTotal - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_key = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name="Api Key",
                                          input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=IDENTIFIER, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        vt = VirusTotalManager(api_key, verify_ssl)
        status = EXECUTION_STATE_COMPLETED
        vt.test_connectivity()
        output_message = u"Connection Established"
        result_value = u"true"
        siemplify.LOGGER.info(u"Finished processing")

    except VirusTotalInvalidAPIKeyManagerError as e:
        siemplify.LOGGER.error(u"Invalid API key was provided. Access is forbidden.")
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Invalid API key was provided. Access is forbidden."

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"General error performing action {}. Error: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()