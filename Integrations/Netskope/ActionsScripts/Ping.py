from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from NetskopeManager import NetskopeManager
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = "Netskope"
PING_SCRIPT_NAME = '{} - Ping'.format(INTEGRATION_NAME)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key',
                                           is_mandatory=True)    
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                           is_mandatory=True, default_value=True, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    connectivity_result = False
    
    try:
        netskope_manager = NetskopeManager(server_address, api_key, verify_ssl=use_ssl)
        netskope_manager.test_connectivity()
        connectivity_result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = "Connected successfully."   
    except Exception as e:
        output_message = 'Failed to connect to the {}! Error is {}'.format(INTEGRATION_NAME, e)
        siemplify.LOGGER.error('Connection to API failed, performing action {}'.format(PING_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(connectivity_result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    
    siemplify.end(output_message, connectivity_result, status)

if __name__ == '__main__':
    main()