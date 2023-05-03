from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SplunkManager import SplunkManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    INTEGRATION_NAME,
    SUBMIT_EVENT_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SUBMIT_EVENT_SCRIPT_NAME

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

    index = extract_action_param(siemplify, param_name='Index', print_value=True, is_mandatory=True)
    event = extract_action_param(siemplify, param_name='Event', print_value=True, is_mandatory=True)
    host = extract_action_param(siemplify, param_name='Host', print_value=True)
    source = extract_action_param(siemplify, param_name='Source', print_value=True)
    source_type = extract_action_param(siemplify, param_name='Sourcetype', print_value=True)

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = SplunkManager(server_address=api_root,
                                username=username,
                                password=password,
                                api_token=api_token,
                                ca_certificate=ca_certificate,
                                verify_ssl=verify_ssl,
                                siemplify_logger=siemplify.LOGGER)

        event = manager.submit_event(index, event, host=host, source=source, source_type=source_type)
        siemplify.result.add_result_json(event.to_json())

        output_message = f'Successfully added a new event to index {index} in {INTEGRATION_NAME}'

    except Exception as e:
        output_message = f"Error executing action '{SUBMIT_EVENT_SCRIPT_NAME}'. Reason: {e}"
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
