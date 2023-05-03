from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from SophosManager import SophosManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, EXECUTE_ALERT_ACTIONS_SCRIPT_NAME, ACTION_TYPES_MAPPING


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = EXECUTE_ALERT_ACTIONS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client ID",
                                            is_mandatory=True, input_type=unicode)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client Secret",
                                                is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    # Action parameters
    alert_id = extract_action_param(siemplify, param_name="Alert ID", print_value=True, is_mandatory=True, input_type=unicode)
    action = extract_action_param(siemplify, param_name="Action", print_value=True, is_mandatory=True, input_type=unicode)
    message = extract_action_param(siemplify, param_name="Message", print_value=True, is_mandatory=False, input_type=unicode)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    action = ACTION_TYPES_MAPPING.get(action)
    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = SophosManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                verify_ssl=verify_ssl, test_connectivity=True)

        manager.execute_alert_action(alert_id=alert_id, action=action, message=message)
        output_message = u"Successfully initiated execution of the action {} for the Alert with ID {} in {}".\
            format(action, alert_id, INTEGRATION_DISPLAY_NAME)

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(EXECUTE_ALERT_ACTIONS_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = u"Error executing action {}. Reason: {}".format(EXECUTE_ALERT_ACTIONS_SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result: {}".format(result))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
