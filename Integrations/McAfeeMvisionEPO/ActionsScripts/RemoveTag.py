from SiemplifyAction import SiemplifyAction
from McAfeeMvisionEPOManager import McAfeeMvisionEPOManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param
from constants import REMOVE_TAG_SCRIPT_NAME, INTEGRATION_NAME
from exceptions import TagNotFoundException, EndpointNotFoundException
from SiemplifyDataModel import EntityTypes


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = REMOVE_TAG_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # Configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client ID',
                                            is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client Secret',
                                                is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    scopes = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Scopes',
                                         is_mandatory=True)

    group_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Group Name')

    # Parameters
    tag_name = extract_action_param(siemplify, param_name='Tag Name', is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    enriched_entities = []
    output_message = ''
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS
                         or entity.entity_type == EntityTypes.HOSTNAME]
    try:
        manager = McAfeeMvisionEPOManager(api_root, client_id, client_secret, scopes, group_name, verify_ssl,
                                          siemplify.LOGGER)
        tag = manager.find_tag_or_fail(tag_name)

        for entity in suitable_entities:
            try:
                siemplify.LOGGER.info('\n\nStarted processing entity: {}'.format(entity.identifier))

                device = manager.find_entity_or_fail(entity.identifier,
                                                     is_host=entity.entity_type == EntityTypes.HOSTNAME)
                manager.add_or_remove_tag(device, tag, add=False)
                enriched_entities.append(entity)
                msg = 'Successfully removed tag {} from {}'.format(tag_name, entity.identifier)
                siemplify.LOGGER.info(msg)
                output_message += '\n\n{}'.format(msg)
            except EndpointNotFoundException:
                failed_entities.append(entity)
                msg = "Action wasn't able to remove tag '{0}' from {1}. Reason: Endpoint {1} was not found in McAfee Mvision ePO.".format(
                    tag_name, entity.identifier)
                siemplify.LOGGER.error(msg)
                output_message += '\n\n{}'.format(msg)
            except Exception as e:
                msg = "Action wasn't able to remove tag '{0}' from {1}.".format(
                    tag_name, entity.identifier)
                output_message += '\n\n{}'.format(msg)
                failed_entities.append(entity)
                siemplify.LOGGER.error(msg)
                siemplify.LOGGER.exception(e)
            siemplify.LOGGER.info('Finished processing entity: {}'.format(entity.identifier))

        if not enriched_entities:
            siemplify.LOGGER.info('\n No entities where processed.')
            output_message = 'No entities where processed.'
            result_value = False

    except TagNotFoundException as e:
        result_value = False
        output_message = "Action wasn’t able to remove tag '{0}'. Reason: Tag '{0}' was not found in McAfee Mvision ePO. Please check for any spelling mistakes. In order to get the list of available tags execute action 'List Tags'".format(
            tag_name)
        siemplify.LOGGER.error(output_message)

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(
            REMOVE_TAG_SCRIPT_NAME, e)
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
