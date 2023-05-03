import sys
import json
from typing import List

from CrowdStrikeManager import CrowdStrikeManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param
from constants import (
    API_ROOT_DEFAULT,
    EXECUTE_COMMAND_SCRIPT_NAME,
    INTEGRATION_NAME,
    PRODUCT_NAME,
    STATUS_NORMAL,
    STATE_ONLINE
)
from utils import get_entity_original_identifier
from exceptions import CrowdStrikeSessionCreatedError, NoSuitableEntitiesException

ENTITIES_MAPPER = {
    EntityTypes.ADDRESS: 'local_ip',
    EntityTypes.HOSTNAME: 'starts_with_name'
}


def start_operation(siemplify, manager, command, suitable_entities):
    command_not_available_entities, not_found_entities, data_not_available_entities, not_accessible_entities, \
        successful_entities = [], [], [], [], []

    output_message = ''
    status = EXECUTION_STATE_INPROGRESS
    result_value = {
        'in_progress': {},
        'completed': {},
        'command_not_available': [],
        'data_not_available': [],
        'not_found': [],
        'not_accessible_entities': []
    }
    for entity in suitable_entities:
        entity_identifier = get_entity_original_identifier(entity)
        devices = manager.search_device_ids(**{ENTITIES_MAPPER[entity.entity_type]: entity_identifier})

        if not devices:
            not_found_entities.append(entity_identifier)
            result_value['not_found'].append(entity_identifier)
            continue

        if len(devices) > 1:
            siemplify.LOGGER.info(f"Multiple entries were found for entity: {entity_identifier}. First one is taken")

        try:
            devices_info = manager.get_devices(devices_ids=devices)
            online_state = manager.get_devices_online_states(devices)

            if (devices_info and devices_info[0].status != STATUS_NORMAL) \
                    or (online_state and online_state[0].state != STATE_ONLINE):
                not_accessible_entities.append(entity_identifier)
                result_value['not_accessible_entities'].append(entity_identifier)
                continue

            session_id = manager.create_device_session(device_id=devices[0])
            if not session_id:
                data_not_available_entities.append(entity_identifier)
                result_value['data_not_available'].append(entity_identifier)
                continue

            cloud_request_id = manager.execute_responder_command(session_id=session_id, command=command,
                                                                 device_id=devices[0])
            if not cloud_request_id:
                command_not_available_entities.append(entity_identifier)
                result_value['command_not_available'].append(entity_identifier)
                continue

            result_value['in_progress'][entity_identifier] = cloud_request_id
            successful_entities.append(entity_identifier)
        except CrowdStrikeSessionCreatedError as e:
            data_not_available_entities.append(entity_identifier)
            result_value['data_not_available'].append(entity_identifier)
            siemplify.LOGGER.error(f'An error occurred on entity {entity_identifier}')
            siemplify.LOGGER.exception(e)

        except Exception as e:
            command_not_available_entities.append(entity_identifier)
            result_value['command_not_available'].append(entity_identifier)
            siemplify.LOGGER.error(f'An error occurred on entity {entity_identifier}')
            siemplify.LOGGER.exception(e)

    if successful_entities:
        output_message = f'Successfully created sessions for the following endpoints in {PRODUCT_NAME}: ' \
                         f'{", ".join(successful_entities)}\n'
        result_value = json.dumps(result_value)

        if data_not_available_entities:
            output_message += f'Action wasn\'t able to created sessions for the following endpoints in ' \
                              f'{PRODUCT_NAME}: {", ".join(data_not_available_entities)}\n'
        if not_accessible_entities:
            output_message += f'Action wasn\'t able to execute command on the following machines: ' \
                              f'{", ".join(not_accessible_entities)}. Reason: machines are not online or not ' \
                              f'accessible. Please validate the connection.\n'

    else:
        if command_not_available_entities and not not_found_entities and not data_not_available_entities \
                and not not_accessible_entities:
            output_message = f"Command '{command}' was not found on the provided endpoints in " \
                             f"{PRODUCT_NAME}."

        elif not_found_entities and not command_not_available_entities and not data_not_available_entities \
                and not not_accessible_entities:
            output_message = f"None of the provided endpoints were found in {PRODUCT_NAME}."

        elif data_not_available_entities and not command_not_available_entities and not not_found_entities \
                and not not_accessible_entities:
            output_message = f"Command '{command}' wasn't executed on the provided endpoints in " \
                             f"{PRODUCT_NAME}.\n"
        elif not_accessible_entities and not data_not_available_entities and not command_not_available_entities and \
                not not_found_entities:
            output_message = f"Action wasn't able to execute command on the provided machines. Reason: machines are " \
                             f"not online or not accessible. Please validate the connection.\n"
        else:
            if command_not_available_entities:
                output_message += f"Command '{command}' was not found on the following endpoints in " \
                                  f"{PRODUCT_NAME}: {', '.join(command_not_available_entities)}\n"
            if not_found_entities:
                output_message += f"The following endpoints were not found in " \
                                  f"{PRODUCT_NAME}: {', '.join(not_found_entities)}\n"
            if data_not_available_entities:
                output_message += f"Action wasn't able to execute command '{command}' on the following endpoints in " \
                                  f"{PRODUCT_NAME}: {', '.join(data_not_available_entities)}\n"
            if not_accessible_entities:
                output_message += f"Action wasn't able to execute command on the following machines: " \
                                  f"{', '.join(not_accessible_entities)}. Reason: machines are not online or not " \
                                  f"accessible. Please validate the connection.\n"

        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status


def query_operation_status(siemplify, manager, sessions, suitable_entities, command_to_execute):
    completed_entities = {}
    for entity, cloud_request_id in sessions['in_progress'].items():
        try:
            commands = manager.get_status_of_responder_command(cloud_request_id=cloud_request_id)
            for single_command in commands:
                if single_command.complete:
                    completed_entities[entity] = single_command.to_json()
        except CrowdStrikeSessionCreatedError as e:
            sessions['data_not_available'].append(entity)
            siemplify.LOGGER.error(f'An error occurred on entity {entity}')
            siemplify.LOGGER.exception(e)

        except Exception as e:
            sessions['command_not_available'].append(entity)
            siemplify.LOGGER.error(f'An error occurred on entity {entity}')
            siemplify.LOGGER.exception(e)

    for key in completed_entities.keys():
        sessions['in_progress'].pop(key)
    for failed_entity in sessions['command_not_available']:
        if failed_entity in sessions['in_progress'].keys():
            sessions['in_progress'].pop(failed_entity)
    for failed_entity in sessions['data_not_available']:
        if failed_entity in sessions['in_progress'].keys():
            sessions['in_progress'].pop(failed_entity)
    sessions['completed'].update(completed_entities)

    if sessions['in_progress']:
        status = EXECUTION_STATE_INPROGRESS
        result_value = json.dumps(sessions)
        output_message = f"Waiting for results for the following entities: {', '.join(sessions['in_progress'].keys())}"
    else:
        output_message, result_value, status = finish_operation(
            siemplify=siemplify,
            command=command_to_execute,
            suitable_entities=suitable_entities,
            completed_entities=sessions['completed'],
            command_not_available_entities=sessions['command_not_available'],
            not_found_entities=sessions['not_found'],
            data_not_available_entities=sessions['data_not_available'],
            not_accessible_entities=sessions['not_accessible_entities'],
        )

    return output_message, result_value, status


def finish_operation(siemplify, command, suitable_entities, completed_entities, command_not_available_entities,
                     not_found_entities, data_not_available_entities, not_accessible_entities):
    result_value = True
    output_message = ''
    status = EXECUTION_STATE_COMPLETED
    command_not_available_entities = command_not_available_entities
    not_found_entities = not_found_entities
    data_not_available_entities = data_not_available_entities
    successful_entities, json_results = [], {}

    for entity in suitable_entities:
        entity_identifier = get_entity_original_identifier(entity)
        if entity_identifier in completed_entities.keys():
            entity_result = completed_entities[entity_identifier]
            json_results[entity_identifier] = entity_result

            successful_entities.append(entity_identifier)

    if successful_entities:
        output_message += f"Successfully executed command '{command}' on the following endpoints in {PRODUCT_NAME}: " \
                          f"{', '.join(successful_entities)}\n"
    if command_not_available_entities:
        output_message += f"Command '{command}' was not found on the following endpoints in " \
                          f"{PRODUCT_NAME}: {', '.join(command_not_available_entities)}\n"
    if not_found_entities:
        output_message += f"The following endpoints were not found in " \
                          f"{PRODUCT_NAME}: {', '.join(not_found_entities)}\n"
    if data_not_available_entities:
        output_message += f"Action wasn't able to execute command '{command}' on the following endpoints in " \
                          f"{PRODUCT_NAME}: {', '.join(data_not_available_entities)}\n"
    if not_accessible_entities:
        output_message += f"Action wasn't able to execute command on the following machines: " \
                          f"{', '.join(not_accessible_entities)}. Reason: machines are not online or not accessible. " \
                          f"Please validate the connection.\n"

    if not successful_entities:
        result_value = False

        if command_not_available_entities and not not_found_entities and not data_not_available_entities and \
                not not_accessible_entities:
            output_message = f"Command '{command}' was not found on the provided endpoints in " \
                             f"{PRODUCT_NAME}.\n"
        elif data_not_available_entities and not not_found_entities and not command_not_available_entities and \
                not not_accessible_entities:
            output_message = f"Command '{command}' wasn't executed on the provided endpoints in " \
                             f"{PRODUCT_NAME}.\n"
        elif not_found_entities and not command_not_available_entities and not data_not_available_entities and \
                not not_accessible_entities:
            output_message = f"None of the provided endpoints were found in {PRODUCT_NAME}.\n"

        elif not_accessible_entities and not data_not_available_entities and not command_not_available_entities and \
                not not_found_entities:
            output_message = f"Action wasn't able to execute command on the provided machines. Reason: machines are " \
                             f"not online or not accessible. Please validate the connection.\n"

    if json_results:
        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = EXECUTE_COMMAND_SCRIPT_NAME
    mode = "Main" if is_first_run else "Get Report"

    siemplify.LOGGER.info(f'----------------- {mode} - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           default_value=API_ROOT_DEFAULT)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Client API ID')
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name='Client API Secret')
    use_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                          input_type=bool, is_mandatory=True)

    command_to_execute = extract_action_param(siemplify, param_name='Command', is_mandatory=True, print_value=True)
    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    status = EXECUTION_STATE_INPROGRESS
    result_value = False
    output_message = ''
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in ENTITIES_MAPPER.keys()]

    try:
        if not suitable_entities:
            raise NoSuitableEntitiesException

        manager = CrowdStrikeManager(client_id=client_id, client_secret=client_secret, use_ssl=use_ssl,
                                     api_root=api_root, force_check_connectivity=True)

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify, manager=manager,
                                                                   command=command_to_execute,
                                                                   suitable_entities=suitable_entities)
        if status == EXECUTION_STATE_INPROGRESS:
            sessions = result_value if result_value else extract_action_param(siemplify, param_name="additional_data",
                                                                              default_value='{}')
            output_message, result_value, status = query_operation_status(siemplify=siemplify, manager=manager,
                                                                          sessions=json.loads(sessions),
                                                                          suitable_entities=suitable_entities,
                                                                          command_to_execute=command_to_execute)

    except NoSuitableEntitiesException:
        output_message = "Action didn't execute any commands. None of the entities are of type Hostname or IP Address."
        status = EXECUTION_STATE_FAILED
    except Exception as e:
        output_message = f"Error executing action {EXECUTE_COMMAND_SCRIPT_NAME}. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
