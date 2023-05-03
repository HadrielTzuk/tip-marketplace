from SiemplifyAction import SiemplifyAction
from IBossManager import IBossManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from constants import PING_SCRIPT_NAME, INTEGRATION_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    cloud_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Cloud API Root',
                                           is_mandatory=True)
    account_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Account API Root',
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                            is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                                is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    connectivity_result = False
    try:
        manager = IBossManager(cloud_api_root, account_api_root, username, password, verify_ssl, siemplify.LOGGER)
        manager.test_connectivity()
        output_message = 'Successfully connected to the IBoss server with the provided connection parameters!'
        siemplify.LOGGER.info(output_message)
        connectivity_result = True
        status = EXECUTION_STATE_COMPLETED
    except Exception as e:
        output_message = 'Failed to connect to the IBoss server! Error is {}'.format(e)
        siemplify.LOGGER.error('Connection to API failed, performing action {}'.format(PING_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)

    siemplify.end(output_message, connectivity_result, status)


if __name__ == '__main__':
    main()
