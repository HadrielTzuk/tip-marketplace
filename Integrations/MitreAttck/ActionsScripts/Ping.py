from SiemplifyUtils import output_handler
from MitreAttckManager import MitreAttckManager, MitreAttckManagerError
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = u"MitreAttck"
SCRIPT_NAME = u"Mitre Att&ck - Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                           param_name=u"API Root", print_value=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=True, input_type=bool, print_value=True)

    manager = MitreAttckManager(api_root, verify_ssl)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    try:
        if manager.test_connectivity():
            output_message = u"Connection Established"
        else:
            output_message = u"Unable to connect to MitreAttack"
            status = EXECUTION_STATE_FAILED
            result_value = u"false"
    except Exception as e:
        siemplify.LOGGER.error(u"Unable to connect to MitreAttack")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = u"Unable to connect to MitreAttack"
        result_value = u"false"

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
