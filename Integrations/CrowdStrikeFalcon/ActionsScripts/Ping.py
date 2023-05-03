from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CrowdStrikeManager import CrowdStrikeManager
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import API_ROOT_DEFAULT, INTEGRATION_NAME, PING_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = True
    output_message = 'Connected successfully.'
    status = EXECUTION_STATE_COMPLETED

    try:
        CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl, api_root=api_root,
                           force_check_connectivity=True)

    except Exception as e:
        output_message = f"Error executing action '{PING_SCRIPT_NAME}'. Reason: {e}"
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
