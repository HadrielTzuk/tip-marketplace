import json
from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from TIPCommon import construct_csv, extract_configuration_param, extract_action_param
from SiemplifyUtils import convert_dict_to_json_result_dict
from constants import LIST_PROCESSES_SCRIPT_NAME, INTEGRATION_NAME, DEFAULT_RESULTS_LIMIT, PROCESSES_CASE_WALL, \
    VENDOR_NAME
from utils import get_entity_original_identifier, get_validated_limit
from AsyncActionStepHandler import AsyncActionStepHandler, ActionStep, FAILED_ENTITY_STATE, \
    COMPLETED_ENTITY_STATE, IN_PROGRESS_ENTITY_STATE, IN_PROGRESS_MSG, ALL_FAILED_MSG, \
    SOME_COMPLETED_MSG, SOME_FAILED_MSG, ENTITY_KEY_FOR_FORMAT
from Factory import ManagerFactory
from CBLiveResponseActionSteps import get_device_id, session_start, session_status_check, initial_step, \
    add_custom_data, FAILED_COMMAND_INIT, FAILED_SESSION_INIT

SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]
ACTION_COMPLETE_OUTPUT_MESSAGES = {
    IN_PROGRESS_MSG: f"Action reached timeout waiting for results for the following entities: {{{ENTITY_KEY_FOR_FORMAT}}}",
    ALL_FAILED_MSG: "No processes were found.",
    SOME_COMPLETED_MSG: f"Returned process list for the following entities: {{{ENTITY_KEY_FOR_FORMAT}}}",
    SOME_FAILED_MSG: f"Action was not able to get process list for the following entities: {{{ENTITY_KEY_FOR_FORMAT}}}",
}

INITIAL_STEP = 'initial_step'
DEVICE_GETTER = 'device'
SESSION_STARTER = 'session_starter'
SESSION_CHECKER = 'session_status'
COMMAND_STARTER = 'command'
COMMAND_CHECKER = 'command_object'

MULTIPLE_DEVICES = 'multiple_devices'
DUPLICATED_DEVICES = 'duplicated_devices'
MISSING_DEVICES = 'missing_devices'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_PROCESSES_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True)
    org_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Organization Key",
                                          is_mandatory=True)
    cb_cloud_api_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Carbon Black Cloud API ID", is_mandatory=True)
    cb_cloud_api_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                          param_name="Carbon Black Cloud API Secret Key",
                                                          is_mandatory=True)
    lr_api_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Live Response API ID")
    lr_api_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                    param_name="Live Response API Secret Key")
    use_new_api_version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, input_type=bool,
                                                      param_name="Use Live Response V6 API")

    process_name = extract_action_param(siemplify, param_name='Process Name', print_value=True)
    max_results = extract_action_param(siemplify, param_name='How Many Records To Return', print_value=True,
                                       input_type=int, default_value=DEFAULT_RESULTS_LIMIT)
    executing_limit_per_entity = extract_action_param(siemplify, param_name='Check for active session x times',
                                                      print_value=True, is_mandatory=True, input_type=int)
    max_results = get_validated_limit(max_results)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    json_result = {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    sorted_suitable_entities = sorted(suitable_entities, key=lambda entity: entity.entity_type == EntityTypes.HOSTNAME,
                                      reverse=True)

    try:
        manager = ManagerFactory.create_manager(
            api_root=api_root,
            org_key=org_key,
            cb_cloud_api_id=cb_cloud_api_id,
            cb_cloud_api_secret_key=cb_cloud_api_secret_key,
            lr_api_id=lr_api_id,
            lr_api_secret_key=lr_api_secret_key,
            force_check_connectivity=True,
            use_new_api_version=use_new_api_version
        )

        action_steps = {
            0: ActionStep(step_id=INITIAL_STEP, step_label='Initial step', method_name='initial_step',
                          variables={'suitable_entities': [get_entity_original_identifier(entity)
                                                           for entity in sorted_suitable_entities]}),
            1: ActionStep(step_id=DEVICE_GETTER, step_label='Get Corresponding CB Cloud Device',
                          method_name='get_device_id'),
            2: ActionStep(step_id=SESSION_STARTER, step_label='Session Start', method_name='session_start',
                          variables={'previous_step': DEVICE_GETTER}),
            3: ActionStep(step_id=SESSION_CHECKER, step_label='Session Check', method_name='session_status_check',
                          retry=executing_limit_per_entity, wait_before_retry=2,
                          variables={'previous_step': SESSION_STARTER}),
            4: ActionStep(step_id=COMMAND_STARTER, step_label='Command Start', method_name='command_start'),
            5: ActionStep(step_id=COMMAND_CHECKER, step_label='Command Check', method_name='command_check', retry=5,
                          wait_before_retry=30, variables={'json_result': json_result, 'process_name': process_name,
                                                           'max_rows_to_return': max_results})
        }

        result_value = json.loads(extract_action_param(siemplify, param_name="additional_data", default_value='{}'))
        step_handler = AsyncActionStepHandler(siemplify, manager, action_steps, result_value, globals())
        output_message, result_value, status = step_handler.execute_steps()
        if isinstance(result_value, dict):
            result_value = json.dumps(result_value)

    except Exception as e:
        output_message = f"Failed to execute {LIST_PROCESSES_SCRIPT_NAME} action! Error is {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)


def command_start(step_handler):
    for entity in step_handler.get_entities_by_state(state=IN_PROGRESS_ENTITY_STATE):
        step_handler.logger.info(f"Start processing entity {entity}")
        session_id = step_handler.get_entity_data(entity, SESSION_STARTER)

        try:
            step_handler.logger.info(f"Starting command for list files")
            command = step_handler.manager.start_command_for_process_list(session_id=session_id)
            step_handler.add_entity_data_to_step(entity, command.id)
        except Exception as err:
            error_msg = f"An error occurred while getting data about command for session {session_id}."
            step_handler.logger.error(error_msg)
            step_handler.logger.exception(err)
            add_custom_data(step_handler, FAILED_COMMAND_INIT, entity)
            step_handler.fail_entity(entity, reason=error_msg)
        step_handler.logger.info(f"Finishing processing entity {entity}")


def command_check(step_handler, json_result, process_name, max_rows_to_return):
    step_handler.add_output_messages(ACTION_COMPLETE_OUTPUT_MESSAGES)
    for entity in step_handler.get_entities_by_state(state=IN_PROGRESS_ENTITY_STATE):
        step_handler.logger.info(f"Start process entity {entity}")
        session_id = step_handler.get_entity_data(entity, SESSION_STARTER)
        command_id = step_handler.get_entity_data(entity, COMMAND_STARTER)

        try:
            step_handler.logger.info(f"Getting command")
            command = step_handler.manager.get_process_command_by_id(
                session_id=session_id,
                command_id=command_id,
                process_name=process_name,
                limit=max_rows_to_return
            )
            if command.is_completed or command.is_failed:
                step_handler.logger.info(f"Command is ready.")
                if command.processes:
                    step_handler.add_entity_data_to_step(entity, command)
                else:
                    step_handler.fail_entity(entity, reason='No processes found')
                add_case_wall_data(step_handler, command.processes, entity)
                json_result = collect_json_result(entity, command, json_result)
        except Exception as err:
            error_msg = f"An error occurred while getting data about command {command_id} for session {session_id}."
            step_handler.logger.error(error_msg)
            step_handler.logger.exception(err)
            step_handler.fail_entity(entity, reason=error_msg)
        step_handler.logger.info(f"Finishing processing entity {entity}")

    add_custom_output_messages(step_handler)
    if json_result:
        step_handler.json_result = json_result


def add_custom_output_messages(step_handler):
    message = ''

    if step_handler.get_custom_variable(MULTIPLE_DEVICES):
        message += f"Multiple matches were found in {VENDOR_NAME}, taking agent with the most recent last_contact_time" \
                   f" the following entities: {', '.join(step_handler.get_custom_variable(MULTIPLE_DEVICES))}\n"

    if step_handler.get_custom_variable(DUPLICATED_DEVICES):
        message += "Provided IP and Hostname entities reference the same CB agent, taking Hostname entity for the " \
                   "following Hostname:IP pairs: {}\n".format(', '.join(['{} - {}'.format(item[0], item[1])
                                                                         for item in step_handler
                                                                        .get_custom_variable(DUPLICATED_DEVICES)]))

    if step_handler.get_custom_variable(FAILED_SESSION_INIT):
        message += f"Failed to initiate Live Response session for the following entities: " \
                   f"{', '.join(step_handler.get_custom_variable(FAILED_SESSION_INIT))}\n"

    if step_handler.get_custom_variable(FAILED_COMMAND_INIT):
        message += f"Failed to run command via Live Response session for the following entities: " \
                   f"{', '.join(step_handler.get_custom_variable(FAILED_COMMAND_INIT))}\n"

    if message:
        step_handler.add_addition_output_message(message)


def add_case_wall_data(step_handler, processes, entity):
    if processes:
        step_handler.siemplify.result.add_data_table(
            PROCESSES_CASE_WALL.format(entity),
            construct_csv([process.to_table() for process in processes])
        )


def collect_json_result(entity, command, json_result):
    json_result[entity] = [process.to_json() for process in command.processes]

    return json_result


if __name__ == '__main__':
    main()