from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TaniumManager import TaniumManager
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Token',
                                            is_mandatory=True, remove_whitespaces=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, print_value=True)

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f'Successfully connected to the {INTEGRATION_NAME} installation with the provided connection ' \
                     f'parameters!'

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    try:
        TaniumManager(api_root=api_root, api_token=api_token, verify_ssl=verify_ssl, force_check_connectivity=True)
    except Exception as e:
        output_message = f"Failed to connect to the {INTEGRATION_NAME} installation! Error is {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
