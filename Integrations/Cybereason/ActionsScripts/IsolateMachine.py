import json
import sys
from CybereasonManager import CybereasonManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, unix_now
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, ISOLATE_MACHINE_SCRIPT_NAME, DEFAULT_TIMEOUT
from exceptions import CybereasonManagerNotFoundError
from utils import get_entity_original_identifier, is_approaching_timeout, is_async_action_global_timeout_approaching


def start_operation(siemplify, manager, suitable_entities):
    successful_entities, failed_entities = [], []
    result_value = {
        'for_isolate': {},
        'already_isolated': {},
        'completed': {},
        'failed': [],
        'not_found': []
    }
    status = EXECUTION_STATE_INPROGRESS

    for entity in suitable_entities:
        entity_identifier = get_entity_original_identifier(entity)
        siemplify.LOGGER.info(f"Started processing entity: {entity_identifier}")

        try:
            machine = manager.get_machine_by_name_or_fqdn(machine_identifier=entity_identifier)

            if machine.is_isolated:
                siemplify.LOGGER.info(f"The following machine already isolated: {entity_identifier}")
                result_value['completed'][entity_identifier] = machine.pylum_id
                successful_entities.append(entity_identifier)
                continue

            manager.isolate_machine(machine_pylum_id=machine.pylum_id)
            result_value['for_isolate'][entity_identifier] = machine.pylum_id
            successful_entities.append(entity_identifier)

        except CybereasonManagerNotFoundError as err:
            failed_entities.append(entity_identifier)
            result_value['not_found'].append(entity_identifier)
            siemplify.LOGGER.error(f"Machine with {entity_identifier} value not found in {INTEGRATION_NAME}")
            siemplify.LOGGER.exception(err)
        except Exception as err:
            failed_entities.append(entity_identifier)
            result_value['failed'].append(entity_identifier)
            siemplify.LOGGER.error("An error occurred on entity {}".format(entity_identifier))
            siemplify.LOGGER.exception(err)

    if successful_entities:
        result_value = json.dumps(result_value)
        output_message = f"Successfully found machines in {INTEGRATION_NAME}: {', '.join(successful_entities)}."
    else:
        output_message = f"None of the machines were found in {INTEGRATION_NAME}."
        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status


def query_operation_status(siemplify, manager, action_start_time, result_data, suitable_entities):
    completed_machines = {}
    timeout_approaching = False
    items_to_isolate_count = len(result_data['for_isolate'].keys())

    for entity_identifier, machine_pylum_id in result_data['for_isolate'].items():
        if is_async_action_global_timeout_approaching(siemplify, action_start_time):
            siemplify.LOGGER.info('Timeout is approaching. Action will gracefully exit')
            timeout_approaching = True
            break
        if is_approaching_timeout(action_start_time, DEFAULT_TIMEOUT):
            siemplify.LOGGER.info(f"Action processed {len(completed_machines.keys())} out of {items_to_isolate_count}")
            break

        siemplify.LOGGER.info(f"Isolating machine for {entity_identifier} entity.")
        try:
            machine = manager.get_machine_by_name_or_fqdn(machine_identifier=entity_identifier)

            if not machine.is_isolated:
                continue

            siemplify.LOGGER.info(f"Machine with {machine_pylum_id} pylum id isolated: {entity_identifier}")
            completed_machines[entity_identifier] = machine_pylum_id

        except CybereasonManagerNotFoundError as err:
            result_data['not_found'].append(entity_identifier)
            siemplify.LOGGER.error(f"Machine with {entity_identifier} value not found in {INTEGRATION_NAME}")
            siemplify.LOGGER.exception(err)
        except Exception as err:
            result_data['failed'].append(entity_identifier)
            siemplify.LOGGER.error("An error occurred on entity {}".format(entity_identifier))
            siemplify.LOGGER.exception(err)

    for key in completed_machines.keys():
        result_data['for_isolate'].pop(key)
    # Update completed entities with completed_entities dict including json_result
    result_data['completed'].update(completed_machines)

    if result_data['for_isolate'] and not timeout_approaching:
        status = EXECUTION_STATE_INPROGRESS
        result_value = json.dumps(result_data)
        output_message = f"Waiting for isolation to finish on the following entities: " \
                         f"{', '.join(result_data['for_isolate'].keys())}"
    else:
        output_message, result_value, status = finish_operation(suitable_entities=suitable_entities,
                                                                result_data=result_data,
                                                                timeout_approaching=timeout_approaching)

    return output_message, result_value, status


def finish_operation(suitable_entities, result_data, timeout_approaching):
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    failed_entities = result_data['failed']
    not_found_entities = result_data['not_found']
    not_finished = []
    successful_entities = []
    output_message = ""

    for entity in suitable_entities:
        entity_identifier = get_entity_original_identifier(entity)
        if entity_identifier in result_data['completed'].keys():
            successful_entities.append(entity_identifier)
        if entity_identifier in result_data['for_isolate'].keys():
            not_finished.append(entity_identifier)
    if successful_entities:
        output_message += f"Successfully isolated the following machines in {INTEGRATION_NAME}: " \
                          f"{', '.join(successful_entities)}. \n"
    if failed_entities:
        output_message += f"Action wasn't able to isolate the following machines in {INTEGRATION_NAME}: " \
                          f"{', '.join(failed_entities)} \n"
    if not_found_entities:
        output_message += f"The following machines were not found in {INTEGRATION_NAME}: " \
                          f"{', '.join(not_found_entities)} \n"
    if timeout_approaching and not_finished:
        output_message += f"Isolation was initiated on the following entities, but wasn\'t finished: " \
                          f"{', '.join(not_finished)}. Please execute the action again with bigger timeout.\n"
        status = EXECUTION_STATE_FAILED
        result_value = False
    if not output_message:
        output_message += f"None of the machines were found in {INTEGRATION_NAME}."
        result_value = False

    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    action_start_time = unix_now()
    siemplify.script_name = ISOLATE_MACHINE_SCRIPT_NAME
    mode = "Main" if is_first_run else "Get Report"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='API Root',
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=False, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    output_message = ""
    status = EXECUTION_STATE_INPROGRESS
    result_value = False
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.HOSTNAME]

    try:
        manager = CybereasonManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl,
                                    logger=siemplify.LOGGER, force_check_connectivity=True)

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify, manager=manager,
                                                                   suitable_entities=suitable_entities)
        if status == EXECUTION_STATE_INPROGRESS:
            result_data = result_value if result_value else extract_action_param(siemplify,
                                                                                 param_name="additional_data",
                                                                                 default_value='{}')
            output_message, result_value, status = query_operation_status(siemplify=siemplify, manager=manager,
                                                                          action_start_time=action_start_time,
                                                                          result_data=json.loads(result_data),
                                                                          suitable_entities=suitable_entities)

    except Exception as err:
        output_message = f"Error executing action {ISOLATE_MACHINE_SCRIPT_NAME}. Reason: {err}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
