from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_unixtime_to_datetime
from constants import INTEGRATION_NAME, UPDATE_ALARM_SCRIPT_NAME, ALARM_STATUS_MAPPING
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from LogRhythmManager import LogRhythmRESTManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_ALARM_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    alarm_id = extract_action_param(siemplify, param_name="Alarm ID", is_mandatory=True)
    alarm_status = ALARM_STATUS_MAPPING.get(extract_action_param(siemplify, param_name="Status",
                                                                 default_value="Select One"))
    risk_score = extract_action_param(siemplify, param_name="Risk Score", input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = f"Successfully updated alarm with ID {alarm_id} in {INTEGRATION_NAME}."

    try:
        manager = LogRhythmRESTManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl)

        if alarm_status is None and risk_score is None:
            raise Exception("at least one of the action parameters should have a provided value.")
        manager.update_alarm(alarm_id=alarm_id, alarm_status=alarm_status, risk_score=risk_score)

    except Exception as e:
        output_message = f"Error executing action {UPDATE_ALARM_SCRIPT_NAME}. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
