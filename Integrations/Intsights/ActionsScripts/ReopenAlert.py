from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from IntsightsManager import IntsightsManager
from exceptions import AlertNotFoundError
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from consts import (
    INTEGRATION_NAME,
    REOPEN_ALERT_ACTION
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REOPEN_ALERT_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    account_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Account ID",
                                             is_mandatory=True, print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          is_mandatory=True, print_value=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True, print_value=True)

    alert_id = extract_action_param(siemplify, param_name="Alert ID", is_mandatory=True, print_value=True)
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    
    try:
        intsight_manager = IntsightsManager(server_address=api_root, account_id=account_id, api_key=api_key,
                                            api_login=False, verify_ssl=verify_ssl, force_check_connectivity=True)
        intsight_manager.reopen_alert(alert_id=alert_id)
        output_message = f"Successfully reopened the alert with ID {alert_id} in Intsights"
    
    except AlertNotFoundError as e:
        output_message += f"Action was not able to reopen the alert with ID {alert_id} in Intsights. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False        
    
    except Exception as e:
        output_message = f"Error executing action {REOPEN_ALERT_ACTION}. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
