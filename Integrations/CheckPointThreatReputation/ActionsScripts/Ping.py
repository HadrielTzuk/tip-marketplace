from SiemplifyAction import SiemplifyAction
from CheckPointThreatReputationManager import CheckPointThreatReputationManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from constants import PING_SCRIPT_NAME, INTEGRATION_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Key',
                                          is_mandatory=True)

    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, default_value=True, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    connectivity_result = 'false'

    try:
        manager = CheckPointThreatReputationManager(api_root=api_root, api_key=api_key, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        manager.test_connectivity()
        output_message = 'Successfully connected to the CheckPoint Threat Reputation service with the provided connection parameters!'
        siemplify.LOGGER.info(output_message)
        connectivity_result = 'true'
        status = EXECUTION_STATE_COMPLETED
    except Exception as e:
        output_message = 'Failed to connect to the CheckPoint Threat Reputation server! Error is {}'.format(e)
        siemplify.LOGGER.error('Connection to API failed, performing action {}'.format(PING_SCRIPT_NAME))
        siemplify.LOGGER.exception(e)

    siemplify.end(output_message, connectivity_result, status)


if __name__ == '__main__':
    main()
