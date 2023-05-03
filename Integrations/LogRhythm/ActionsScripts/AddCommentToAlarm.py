from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from constants import INTEGRATION_NAME, ADD_COMMENT_TO_ALARM_SCRIPT_NAME
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from LogRhythmManager import LogRhythmRESTManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_COMMENT_TO_ALARM_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    alarm_id = extract_action_param(siemplify, param_name="Alarm ID", is_mandatory=True)
    comment = extract_action_param(siemplify, param_name="Comment", is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = f"Successfully added comment to the alarm with ID {alarm_id} in {INTEGRATION_NAME}."

    try:
        manager = LogRhythmRESTManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl,
                                       force_check_connectivity=True)

        manager.add_comment_to_alarm(alarm_id, comment)

    except Exception as e:
        output_message = f"Error executing action 'Add Comment To Alarm'. Reason: {e} ."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
