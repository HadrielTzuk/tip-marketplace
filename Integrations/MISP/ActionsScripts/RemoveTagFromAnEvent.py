from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MISPManager import MISPManager, REMOVE_ACTION
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, REMOVE_TAG_FROM_AN_EVENT_SCRIPT_NAME
from exceptions import MISPManagerEventIdNotFoundError, MISPManagerTagNotFoundError
from utils import string_to_multi_value


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REMOVE_TAG_FROM_AN_EVENT_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root')

    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Use SSL',
                                          default_value=False, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="CA Certificate File - parsed into Base64 String")

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    # INIT ACTION PARAMETERS:
    event_id = extract_action_param(siemplify, param_name='Event ID', print_value=True, is_mandatory=True)
    id_type = 'ID' if event_id is not None and event_id.isdigit() else 'UUID'
    tag_names = string_to_multi_value(extract_action_param(siemplify, param_name='Tag Name', is_mandatory=True,
                                                           print_value=True))

    result_value = False
    status = EXECUTION_STATE_COMPLETED
    removed_tags = []
    not_removed_tags = []

    try:
        manager = MISPManager(api_root, api_token, use_ssl, ca_certificate)
        # Tag add\remove endpoint isn't giving a correct message in case of invalid event id
        request_event_id = manager.get_event_by_id_or_raise(event_id).id

        remove_tag_responses = []
        tags_with_name, not_existing_tag_names = manager.find_tags_with_names(tag_names)

        for tag_name, tag in tags_with_name.items():
            response = manager.add_or_remove_tag(REMOVE_ACTION, request_event_id, tag.id)
            remove_tag_responses.append(response)
            (removed_tags if response.is_saved else not_removed_tags).append(tag_name)

        if removed_tags:
            result_value = True
            output_message = 'Successfully removed the following tags from the event with {} {} in {}:\n   {}\n' \
                .format(id_type, event_id, INTEGRATION_NAME, '\n   '.join(removed_tags))

            if not_removed_tags:
                output_message += 'Action wasn’t able to remove the following tags from the event with {} {} in {} ' \
                                  ':\n   {}\n' \
                    .format(id_type, event_id, INTEGRATION_NAME, '\n   '.join(not_removed_tags))
        else:
            output_message = 'No tags were removed from the event with {} {} in {}\n' \
                .format(id_type, event_id, INTEGRATION_NAME)

        if not_existing_tag_names:
            if not tags_with_name:
                output_message = 'None of the provided tags were found in {}.\n'.format(INTEGRATION_NAME)
            else:
                output_message += 'The following tags were not found in {}: \n{}'\
                    .format(INTEGRATION_NAME, '\n'.join(not_existing_tag_names))

        if remove_tag_responses:
            siemplify.result.add_result_json([response.to_json() for response in remove_tag_responses])

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: ".format(REMOVE_TAG_FROM_AN_EVENT_SCRIPT_NAME)
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
