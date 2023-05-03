from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ArcsightManager import ArcsightManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from exceptions import ArcsightNoEntitiesFoundError
from constants import INTEGRATION_NAME, ADD_ENTITIES_TO_ACTIVE_LIST
from UtilsManager import get_entity_original_identifier
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_ENTITIES_TO_ACTIVE_LIST
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                           is_mandatory=True)
    ca_certificate_file = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                      param_name='CA Certificate File')
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    entity_column = extract_action_param(siemplify, param_name='Entity Column', print_value=True, is_mandatory=True)
    activelist_name = extract_action_param(siemplify, param_name='Active List Name', print_value=True,
                                           is_mandatory=True)
    additional_fields = extract_action_param(siemplify, param_name='Additional Fields', print_value=True,
                                             default_value='{}')

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = "Successfully added entries to the active list '{0}' in ArcSight.".format(activelist_name)
    suitable_entities = siemplify.target_entities
    entries = {'columns': [entity_column], 'entry_list': []}

    try:
        if not suitable_entities:
            raise ArcsightNoEntitiesFoundError("No entities were added to the active list '{}' in ArcSight"
                                               .format(activelist_name))

        additional_fields = json.loads(additional_fields)
        entries['columns'] += [name for name in additional_fields.keys() if name not in entries['columns']]

        for entity in suitable_entities:
            entries['entry_list'].append(
                [get_entity_original_identifier(entity), *[additional_fields[name] for name in entries['columns'][1:]]])

        arcsight_manager = ArcsightManager(server_ip=api_root, username=username, password=password,
                                           verify_ssl=verify_ssl,
                                           ca_certificate_file=ca_certificate_file, logger=siemplify.LOGGER)
        arcsight_manager.login()

        activelist_uuid = arcsight_manager.get_activelist_uuid(activelist_name)
        arcsight_manager.add_entries_to_activelist_uuid(entries=entries, list_uuid=activelist_uuid)

        arcsight_manager.logout()

    except ArcsightNoEntitiesFoundError as e:
        output_message = str(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(ADD_ENTITIES_TO_ACTIVE_LIST, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
