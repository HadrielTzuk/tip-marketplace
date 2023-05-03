from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from SophosManager import SophosManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, LIST_ALERT_ACTIONS_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ALERT_ACTIONS_SCRIPT_NAME
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

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = SophosManager(api_root=api_root, client_id=client_id, client_secret=client_secret,
                                verify_ssl=verify_ssl, test_connectivity=True)

        actions = manager.get_alert_actions(alert_id=alert_id)

        if actions:
            siemplify.result.add_result_json({"allowedActions": actions})
            output_message = u"Successfully retrieved available actions for the Alert with ID {} in " \
                             u"{}".format(alert_id, INTEGRATION_DISPLAY_NAME)
        else:
            output_message = u"No actions are available for the alert with ID {} in {}".format(alert_id,
                                                                                               INTEGRATION_DISPLAY_NAME)

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(LIST_ALERT_ACTIONS_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = u"Error executing action {}. Reason: {}".format(LIST_ALERT_ACTIONS_SCRIPT_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result: {}".format(result))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
