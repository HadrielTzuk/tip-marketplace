from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from CBCloudManager import CBCloudManager, CBCloudUnauthorizedError
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import INTEGRATION_NAME, DISMISS_ALERT_SCRIPT_NAME, PROVIDER_NAME


NO_DISMISSAL_REASON = "No dismissal reason"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DISMISS_ALERT_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    org_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Organization Key',
                                          is_mandatory=True)
    api_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API ID',
                                         is_mandatory=True)
    api_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Secret Key',
                                                 is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    alert_id = extract_action_param(siemplify, param_name="Alert ID", is_mandatory=True, print_value=True)
    remediation_state = extract_action_param(siemplify, param_name="Reason for dismissal", print_value=True)
    comment = extract_action_param(siemplify, param_name="Message for alert dismissal", print_value=True)
    remediation_state = remediation_state if remediation_state != NO_DISMISSAL_REASON else None

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f'Successfully dismissed {PROVIDER_NAME} alert with alert id {alert_id}'

    try:
        manager = CBCloudManager(api_root=api_root, org_key=org_key, api_id=api_id, api_secret_key=api_secret_key,
                                 verify_ssl=verify_ssl)
        manager.dismiss_alert(alert_id=alert_id, remediation_state=remediation_state, comment=comment)

    except Exception as e:
        output_message = f'Error executing action {DISMISS_ALERT_SCRIPT_NAME}. Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
