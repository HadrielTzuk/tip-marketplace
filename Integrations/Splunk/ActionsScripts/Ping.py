from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SplunkManager import SplunkManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()

    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username')
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password')
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             print_value=True, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name='CA Certificate File')

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        SplunkManager(server_address=api_root,
                      username=username,
                      password=password,
                      api_token=api_token,
                      ca_certificate=ca_certificate,
                      verify_ssl=verify_ssl,
                      force_check_connectivity=True,
                      siemplify_logger=siemplify.LOGGER)

        output_message = f'Successfully connected to the {INTEGRATION_NAME} server with the provided connection ' \
                         f'parameters!.'

    except Exception as e:
        output_message = f'Failed to connect to the {PING_SCRIPT_NAME} server! Error is {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
