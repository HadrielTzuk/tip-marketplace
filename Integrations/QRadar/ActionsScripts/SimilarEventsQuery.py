import sys
import json
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, construct_csv
from SiemplifyAction import SiemplifyAction
from QRadarManager import QRadarManager
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from TIPCommon import extract_action_param, extract_configuration_param, string_to_multi_value
from constants import INTEGRATION_NAME, GET_SIMILAR_EVENTS_SCRIPT_NAME, SIMILAR_EVENTS_TABLE_HEADER, TIME_DELTA, LIMIT,\
    EVENTS_DATA_TYPE_IDENTIFIER
from UtilsManager import get_entity_original_identifier
from exceptions import QRadarValidationError

SUITABLE_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.USER, EntityTypes.HOSTNAME]


def start_operation(siemplify, manager, suitable_entities):
    time_delta = extract_action_param(siemplify, param_name='Time Delta In Minutes', print_value=True, input_type=int,
                                      default_value=TIME_DELTA)
    events_limit_to_fetch = extract_action_param(siemplify, param_name='Events Limit To Fetch', print_value=True,
                                                 input_type=int, default_value=LIMIT, is_mandatory=True)
    fields_to_display = string_to_multi_value(extract_action_param(siemplify, param_name='Fields To Display',
                                                                   print_value=True))

    hostname_field = extract_action_param(siemplify, param_name='Hostname Field Name', print_value=True)
    source_address_field = extract_action_param(siemplify, param_name='Source IP Address Field Name', print_value=True)
    destination_address_field = extract_action_param(siemplify, param_name='Destination IP Address Field Name',
                                                     print_value=True)
    username_field = extract_action_param(siemplify, param_name='Username Field Name', print_value=True)

    result_value = {
        'in_progress': {},
        'completed': {},
        'failed': [],
        'entities': [get_entity_original_identifier(entity) for entity in suitable_entities]
    }
    output_message = ""
    invalid_parameter_output_message = ""
    status = EXECUTION_STATE_INPROGRESS
    successful_entities, failed_entities, invalid_field_entities = [], [], []

    for entity in suitable_entities:
        try:
            search_id = manager.search_for_items(entity=get_entity_original_identifier(entity),
                                                 entity_type=entity.entity_type, action_type=EVENTS_DATA_TYPE_IDENTIFIER,
                                                 time_delta=time_delta, limit=events_limit_to_fetch,
                                                 fields=fields_to_display, source_address_field=source_address_field,
                                                 destination_address_field=destination_address_field,
                                                 hostname_field=hostname_field, username_field=username_field)

            result_value['in_progress'][get_entity_original_identifier(entity)] = search_id
            successful_entities.append(get_entity_original_identifier(entity))

        except QRadarValidationError as err:
            invalid_field_entities.append(get_entity_original_identifier(entity))
            result_value['failed'].append(get_entity_original_identifier(entity))
            siemplify.LOGGER.error("An error occurred on entity {}".format(get_entity_original_identifier(entity)))
            siemplify.LOGGER.exception(err)
            invalid_parameter_output_message = str(err)

        except Exception as err:
            failed_entities.append(get_entity_original_identifier(entity))
            result_value['failed'].append(get_entity_original_identifier(entity))
            siemplify.LOGGER.error("An error occurred on entity {}".format(get_entity_original_identifier(entity)))
            siemplify.LOGGER.exception(err)

    if successful_entities:
        output_message += "Waiting for results for the following entities: {} \n"\
            .format(', '.join(successful_entities))
        result_value = json.dumps(result_value)

    elif invalid_field_entities and not failed_entities:
        output_message = "Action didnt complete successfully because {0}".format(invalid_parameter_output_message)
        result_value = False
        status = EXECUTION_STATE_COMPLETED

    else:
        output_message = "No similar events were found."
        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status


def query_operation_status(siemplify, manager, result):
    completed_entities = {}

    for identifier, search_id in result['in_progress'].items():
        try:
            if manager.is_search_completed(search_id):
                completed_entities[identifier] = search_id
        except Exception as err:
            siemplify.LOGGER.error("An error occurred on search_id {}".format(search_id))
            siemplify.LOGGER.exception(err)

    for key in completed_entities.keys():
        result['in_progress'].pop(key)
    # Update completed entities with completed_entities dict including json_result
    result['completed'].update(completed_entities)

    if result['in_progress']:
        status = EXECUTION_STATE_INPROGRESS
        result_value = json.dumps(result)
        output_message = "Waiting for results for the following entities: {} \n"\
            .format(", ".join(result['in_progress'].keys()))
    else:
        output_message, result_value, status = finish_operation(siemplify=siemplify, manager=manager,
                                                                completed_entities=result['completed'],
                                                                failed_entities=result['failed'],
                                                                suitable_entities_identifiers=result['entities'])

    return output_message, result_value, status


def finish_operation(siemplify, manager, completed_entities, failed_entities, suitable_entities_identifiers):
    json_results = {}
    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities, not_found_entities = [], []

    for entity_identifier in suitable_entities_identifiers:
        if entity_identifier not in completed_entities.keys():
            if entity_identifier not in failed_entities:
                not_found_entities.append(entity_identifier)
            continue

        search_id = completed_entities[entity_identifier]

        try:
            entity_result = manager.get_search_report(search_id=search_id, report_type=EVENTS_DATA_TYPE_IDENTIFIER)
            if entity_result:
                siemplify.result.add_data_table(
                    SIMILAR_EVENTS_TABLE_HEADER.format(entity_identifier),
                    construct_csv([data.to_csv() for data in entity_result]))
                json_results[entity_identifier] = [data.to_json() for data in entity_result]
                successful_entities.append(entity_identifier)
            else:
                if entity_identifier not in failed_entities:
                    not_found_entities.append(entity_identifier)

        except Exception as err:
            failed_entities.append(entity_identifier)
            siemplify.LOGGER.error("An error occurred on search_id {}".format(search_id))
            siemplify.LOGGER.exception(err)

    if json_results:
        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    if successful_entities:
        output_message += "Similar events were found for the following entities:\n {} \n"\
            .format(', '.join(successful_entities))

    if not_found_entities:
        output_message += "The following entities were processed successfully, but no similar events were found for " \
                          "them:\n{}\n".format(', '.join(not_found_entities))

    if failed_entities:
        output_message += "Failed processing of the following entities:\n {} \n".format(', '.join(failed_entities))

    if not successful_entities:
        output_message = "No similar events were found."
        result_value = False

    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_SIMILAR_EVENTS_SCRIPT_NAME

    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Token",
                                            is_mandatory=True)
    api_version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Version")

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUITABLE_ENTITY_TYPES]

    output_message = ""
    result_value = False
    status = EXECUTION_STATE_INPROGRESS

    try:
        manager = QRadarManager(api_root, api_token, api_version)
        if is_first_run:
            output_message, result_value, status = start_operation(siemplify=siemplify, manager=manager,
                                                                   suitable_entities=suitable_entities)

        if status == EXECUTION_STATE_INPROGRESS:
            result = result_value if result_value else extract_action_param(siemplify, param_name="additional_data",
                                                                            default_value='{}')

            output_message, result_value, status = query_operation_status(siemplify, manager=manager,
                                                                          result=json.loads(result))
    except Exception as err:
        output_message = "Failed to execute action, the error is {}".format(err)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
