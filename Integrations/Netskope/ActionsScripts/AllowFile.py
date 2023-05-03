from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from NetskopeManager import NetskopeManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = "Netskope"
ALLOWFILE_SCRIPT_NAME = '{} - AllowFile'.format(INTEGRATION_NAME)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ALLOWFILE_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key',
                                           is_mandatory=True)    
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                           is_mandatory=True, default_value=True, input_type=bool)

    # Parameters
    file_id = extract_action_param(siemplify, param_name='File ID', is_mandatory=True)
    quarantine_profile_id = extract_action_param(siemplify, param_name='Quarantine Profile ID', is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    result_value = False

    try:
        netskope_manager = NetskopeManager(server_address, api_key, verify_ssl=verify_ssl)
        netskope_manager.allow_file(file_id, quarantine_profile_id)
        result_value = True
        status = EXECUTION_STATE_COMPLETED
        output_message = "Successfully allowed file {}".format(file_id)
        
    except Exception as e:
        
        output_message = "Error executing action \"AllowFile\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED        
    
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    
    siemplify.end(output_message, result_value, status)
  
if __name__ == "__main__":
    main()