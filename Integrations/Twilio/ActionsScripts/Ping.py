from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TwilioManager import TwilioManager
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    PING_ACTION
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    # INIT INTEGRATION CONFIGURATION:
    account_sid = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="AccountSid",
                                           input_type=str)
    auth_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="AuthenticationToken",
                                          input_type=str)
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    
    try:
        twilio_manager = TwilioManager(account_sid, auth_token)
        twilio_manager.test_connectivity()
        output_message = "Connection Established."
        
    except Exception as e:
        output_message = 'Error executing action \"Ping\". Reason: {}'.format(e)
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
