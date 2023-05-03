from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TwilioManager import TwilioManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    SEND_SMS_ACTION
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEND_SMS_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    # INIT INTEGRATION CONFIGURATION:
    account_sid = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="AccountSid",
                                           input_type=str)
    auth_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="AuthenticationToken",
                                          input_type=str)
    from_number = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="SmsPhoneNumber",
                                          input_type=str)    
    
    phone_number = extract_action_param(siemplify, param_name="Phone Number", is_mandatory=True, print_value=True)
    message = extract_action_param(siemplify, param_name="Message", is_mandatory=True, print_value=True)
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    
    try:
        twilio_manager = TwilioManager(account_sid, auth_token)
        twilio_manager.send_message(to=phone_number, from_=from_number, body=message)
        output_message = "SMS was sent to {0}.\nMessage: {1}".format(phone_number, message)
        
    except Exception as e:
        output_message = "Failed to send the SMS. Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(
        'Status: {}, Result Value: {}, Output Message: {}'
        .format(status, result_value, output_message)
    )        
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
