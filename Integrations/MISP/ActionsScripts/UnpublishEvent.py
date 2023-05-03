from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MISPManager import MISPManager
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, UNPUBLISH_EVENT_SCRIPT_NAME
from exceptions import MISPManagerEventIdNotFoundError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UNPUBLISH_EVENT_SCRIPT_NAME
    status = EXECUTION_STATE_COMPLETED
    result_value = True

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root')
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Use SSL',
                                          default_value=False, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="CA Certificate File - parsed into Base64 String")
    # INIT ACTION PARAMETERS:
    event_id = extract_action_param(siemplify, param_name='Event ID', is_mandatory=True, print_value=True)
    id_type = 'ID' if event_id.isdigit() else 'UUID'

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    try:
        manager = MISPManager(api_root, api_token, use_ssl, ca_certificate, logger=siemplify.LOGGER)

        manager.get_event_by_id_or_raise(event_id)

        event = manager.publish_unpublish_event(event_id, publish=False)

        if event.published:
            output_message = 'Event with {} {} was not unpublished in {}'.format(id_type, event_id, INTEGRATION_NAME)
        else:
            output_message = 'Successfully unpublished event with {} {} in {}'\
                .format(id_type, event_id, INTEGRATION_NAME)

        siemplify.result.add_result_json(event.to_json())

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: ".format(UNPUBLISH_EVENT_SCRIPT_NAME)
        output_message += 'Event with {} {} was not found in {}'.format(id_type, event_id, INTEGRATION_NAME) \
            if isinstance(e, MISPManagerEventIdNotFoundError) else str(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
