from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from consts import INTEGRATION_NAME, ADD_NOTE_ACTION
from IntsightsManager import IntsightsManager
from exceptions import NotFoundError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_NOTE_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    account_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Account ID",
                                             is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key", is_mandatory=True, remove_whitespaces=False
    )
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True, print_value=True)

    alert_id = extract_action_param(siemplify, param_name="Alert ID", is_mandatory=True, print_value=True)
    note = extract_action_param(siemplify, param_name="Note", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = False
    status = EXECUTION_STATE_FAILED

    try:
        intsight_manager = IntsightsManager(server_address=api_root, account_id=account_id, api_key=api_key,
                                            api_login=False, verify_ssl=verify_ssl)

        intsight_manager.add_alert_note(alert_id, note)
        result_value = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully added a note to the alert with ID \"{alert_id}\" in {INTEGRATION_NAME}"

    except NotFoundError as e:
        siemplify.LOGGER.exception(e)
        output_message = f"Error executing action \"{ADD_NOTE_ACTION}\". Reason: alert with ID {alert_id} was not " \
                         f"found in {INTEGRATION_NAME}."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {ADD_NOTE_ACTION}")
        siemplify.LOGGER.exception(e)
        output_message = f"Error executing action \"{ADD_NOTE_ACTION}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
