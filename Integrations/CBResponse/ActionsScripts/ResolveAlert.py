from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from CBResponseManagerLoader import CBResponseManagerLoader

SCRIPT_NAME = u"CBResponse - Resolve Alert"
INTEGRATION_NAME = u"CBResponse"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    status = EXECUTION_STATE_COMPLETED
    result_value = u"true"

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          input_type=unicode)
    version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Version",
                                          input_type=float)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    # INIT PARAMETERS
    alert_id = extract_action_param(siemplify, param_name="Alert ID", is_mandatory=True, print_value=True,
                                    input_type=unicode)

    try:
        manager = CBResponseManagerLoader.load_manager(version, api_root, api_key, siemplify.LOGGER)
        manager.resolve_alert(alert_id)
        output_message = u"Successfully resolved alert {}.".format(alert_id)
    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Some errors occurred. Please check log"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message)
    )
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
