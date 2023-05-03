from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from CBCloudManager import CBCloudManager, CBCloudUnauthorizedError
from TIPCommon import extract_configuration_param
from constants import INTEGRATION_NAME, PING_SCRIPT_NAME, PROVIDER_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    org_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Organization Key',
                                          is_mandatory=True)
    api_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API ID',
                                         is_mandatory=True)
    api_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Secret Key',
                                                 is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = f"Successfully connected to the {PROVIDER_NAME} server with the provided connection parameters!"
    try:
        CBCloudManager(api_root=api_root, org_key=org_key, api_id=api_id, api_secret_key=api_secret_key,
                       verify_ssl=verify_ssl, force_check_connectivity=True)

    except Exception as e:
        output_message = f"Failed to connect to the VMware Carbon Black Cloud server! Error is {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
