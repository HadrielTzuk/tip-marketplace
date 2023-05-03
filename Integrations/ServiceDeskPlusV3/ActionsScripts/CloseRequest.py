from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ServiceDeskPlusManagerV3 import ServiceDeskPlusManagerV3
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    CLOSE_REQUEST_ACTION
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CLOSE_REQUEST_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Api Root", print_value=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Api Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, print_value=True)
    
    # Action Parameters
    comment = extract_action_param(siemplify, param_name="Comment", is_mandatory=True, input_type=str, print_value=True)
    request_id = extract_action_param(siemplify, param_name="Request ID", is_mandatory=True, input_type=str, print_value=True)
    resolution_ack = extract_action_param(siemplify, param_name="Resolution Acknowledged", default_value=False, is_mandatory=False, input_type=bool, print_value=True)
       
    
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        servicedesk_manager = ServiceDeskPlusManagerV3(api_root=api_root,api_key=api_key, verify_ssl=verify_ssl)
        result = servicedesk_manager.close_request(request_id=request_id, resolution_ack=resolution_ack, comment=comment)
        output_message = "Successfully closed ServiceDesk Plus request with ID {}".format(request_id)
        
        siemplify.result.add_result_json(result.to_json())
        
    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(CLOSE_REQUEST_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
