from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from MISPManager import MISPManager, ADD_ACTION
from TIPCommon import extract_configuration_param, extract_action_param
from utils import string_to_multi_value
from constants import INTEGRATION_NAME, ADD_TAG_TO_AN_EVENT_SCRIPT_NAME
from exceptions import MISPManagerEventIdNotFoundError, MISPManagerTagNotFoundError


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_TAG_TO_AN_EVENT_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root")
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key")
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Use SSL",
                                          default_value=False, input_type=bool)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="CA Certificate File - parsed into Base64 String")
    # INIT ACTION PARAMETERS:
    event_id = extract_action_param(siemplify, param_name="Event ID", is_mandatory=True,
                                    print_value=True)
    id_type = 'ID' if event_id is not None and event_id.isdigit() else 'UUID'
    tag_names = string_to_multi_value(extract_action_param(siemplify, param_name="Tag Name", print_value=True))

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = False
    status = EXECUTION_STATE_COMPLETED
    added_tags = []
    not_added_tags = []
    add_tag_responses = []
    try:
        manager = MISPManager(api_root, api_token, use_ssl, ca_certificate)
        request_event_id = manager.get_event_by_id_or_raise(event_id).id
        tags_with_name, not_existing_tag_names = manager.find_tags_with_names(tag_names)

        for tag_name, tag in tags_with_name.items():
            response = manager.add_or_remove_tag(ADD_ACTION, request_event_id, tag_name)
            add_tag_responses.append(response)
            (added_tags if response.is_saved else not_added_tags).append(tag_name)

        if added_tags:
            result_value = True
            output_message = 'Successfully added the following tags to the event with {} {} in {}:\n   {}\n' \
                .format(id_type, event_id, INTEGRATION_NAME, '\n   '.join(added_tags))

            if not_added_tags:
                output_message += 'Action wasn’t able to add the following tags to the event with {} {} in {} ' \
                                  ':\n   {}\n' \
                    .format(id_type, event_id, INTEGRATION_NAME, '\n   '.join(not_added_tags))
        else:
            output_message = 'No tags were added to the event with {} {} in {}\n' \
                .format(id_type, event_id, INTEGRATION_NAME)

        if not_existing_tag_names:
            if not tags_with_name:
                output_message = 'None of the provided tags were found in {}.\n'.format(INTEGRATION_NAME)
            else:
                output_message += 'The following tags were not found in {}: \n{}' \
                    .format(INTEGRATION_NAME, '\n'.join(not_existing_tag_names))

        if add_tag_responses:
            siemplify.result.add_result_json([response.to_json() for response in add_tag_responses])

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: ".format(ADD_TAG_TO_AN_EVENT_SCRIPT_NAME)
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
