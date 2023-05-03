from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from MimecastManager import MimecastManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, REJECT_MESSAGE_ACTION

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REJECT_MESSAGE_ACTION

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    app_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Application ID",
                                            is_mandatory=True, print_value=True)
    app_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Application Key",
                                          is_mandatory=True)
    access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Access Key",
                                             is_mandatory=True)
    secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret Key",
                                             is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    message_id = extract_action_param(siemplify, param_name="Message ID", print_value=True, is_mandatory=True)
    note = extract_action_param(siemplify, param_name="Note", print_value=True, is_mandatory=False)
    reason = extract_action_param(siemplify, param_name="Reason", print_value=True, is_mandatory=False, default_value="Select One")
    notify_sender = extract_action_param(siemplify, param_name="Notify Sender", print_value=True, is_mandatory=False, input_type=bool, default_value=False)
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = MimecastManager(api_root=api_root,
                                  app_id=app_id,
                                  app_key=app_key,
                                  access_key=access_key,
                                  secret_key=secret_key,
                                  verify_ssl=verify_ssl,
                                  siemplify=siemplify)
        
        manager.reject_message(message_id=message_id, note=note, reason=reason, notify_sender=notify_sender)
        
        output_message = f"Successfully rejected message with ID \"{message_id}\" in {INTEGRATION_NAME}."

    except Exception as e:
        output_message = f'Error executing action {REJECT_MESSAGE_ACTION}. Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()