from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from AlienVaultManagerLoader import AlienVaultManagerLoader
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = "AlienVaultAnywhere"
PING_SCRIPT_NAME = '{} - Ping'.format(INTEGRATION_NAME)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Product Version',
                                           is_mandatory=True, default_value="V1")
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                           is_mandatory=True)
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                           is_mandatory=True, default_value=True, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    connectivity_result = False
    
    try:
        alienvault_manager = AlienVaultManagerLoader.load_manager(version, server_address, username, password, use_ssl)
        alienvault_manager.test_connectivity()
        connectivity_result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = "Connected successfully."   
    except Exception as e:
        output_message = 'Failed to connect to the AlienVaultAnywhere! Error is {}'.format(e)
        siemplify.LOGGER.error('Connection to API failed, performing action {}'.format(PING_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)

    siemplify.end(output_message, connectivity_result, status)


if __name__ == '__main__':
    main()
