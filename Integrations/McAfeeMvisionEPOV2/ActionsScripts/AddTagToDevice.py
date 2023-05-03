from SiemplifyAction import SiemplifyAction
from McAfeeMvisionEPOV2Manager import McAfeeMvisionEPOV2Manager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import ADD_TAG_SCRIPT_NAME, INTEGRATION_NAME
from exceptions import TagNotFoundException, DeviceNotFoundException
from SiemplifyDataModel import EntityTypes


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_TAG_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # Configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)

    iam_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='IAM Root',
                                           is_mandatory=True)

    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Key',
                                          is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    scopes = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Scopes',
                                         is_mandatory=True)

    # Parameters
    tag_name = extract_action_param(siemplify, param_name='Tag Name', is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_entities = []
    output_message = ''
    missing_entities = []
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS
                         or entity.entity_type == EntityTypes.HOSTNAME]
    try:
        siemplify.LOGGER.info("Connecting to McAfee Mvision ePO V2.")
        manager = McAfeeMvisionEPOV2Manager(api_root, iam_root, client_id, client_secret, api_key, scopes, verify_ssl,
                                            siemplify.LOGGER)
        siemplify.LOGGER.info("Successfully connected to McAfee Mvision ePO V2.")

        tag = manager.find_tag_or_fail(tag_name)

        for entity in suitable_entities:
            try:
                siemplify.LOGGER.info('Started processing entity: {}'.format(entity.identifier))

                device = manager.find_entity_or_fail(entity.identifier,
                                                     is_host=entity.entity_type == EntityTypes.HOSTNAME)
                manager.add_or_remove_tag(device, tag, add=True)
                successful_entities.append(entity.identifier)
                siemplify.LOGGER.info('Successfully added tag {} to {}'.format(tag_name, entity.identifier))

            except DeviceNotFoundException:
                missing_entities.append(entity.identifier)
                siemplify.LOGGER.error("No device was found for entity: {}".format(entity.identifier))

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error("An error occurred on entity: {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info('Finished processing entity: {}'.format(entity.identifier))

        if successful_entities:
            output_message += 'Successfully added tag {} to the following endpoints from McAfee Mvision ePO V2: \n{}'.format(
                tag_name, '\n'.join(successful_entities))

        else:
            siemplify.LOGGER.info('\n No entities were processed.')
            output_message = 'No entities were processed.'
            result_value = False

        if missing_entities:
            output_message += '\n\nAction was not able to find matching McAfee Mvision ePO V2 devices for the following endpoints: \n{}'.format(
                '\n'.join(missing_entities))

        if failed_entities:
            output_message += '\n\nAction was not able to add tag to the following endpoints from McAfee Mvision ePO V2: \n{}\n'.format(
                '\n'.join(failed_entities))

    except TagNotFoundException:
        result_value = False
        output_message = "Action wasn't able to add tag '{0}'. Reason: Tag '{0}' was not found in McAfee Mvision ePO. " \
                         "Please check for any spelling mistakes. In order to get the list of available tags execute " \
                         "action 'List Tags'".format(tag_name)
        siemplify.LOGGER.error(output_message)

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(ADD_TAG_SCRIPT_NAME, e)
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
