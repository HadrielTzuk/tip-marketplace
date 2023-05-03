import sys
import json

from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS

from TIPCommon import extract_configuration_param, extract_action_param

from McAfeeMvisionEDRManager import McAfeeMvisionEDRManager
from constants import (
    PROVIDER_NAME,
    COMPLETED_STATUS,
    ERROR_STATUS,
    COMPLETED_ERROR_STATUS,
    IN_PROGRESS_STATUS
)

SCRIPT_NAME = u"McAfeeMvisionEDR - Kill Process"


def find_in_host(entity, hosts):
    for host in hosts:
        if entity.identifier.lower() == host.hostname.lower() or entity.identifier in map(lambda item: item.ip,
                                                                          host.net_interfaces):
            return host.ma_guid
    return None


def start_operation(siemplify, manager, pid_type, pid_value):
    """
    Main KillProcess action
    :param siemplify: SiemplifyAction object
    :param manager: McAfeeMvisionEDRManager object
    :param pid_type: {unicode} Process identifier type.
    :param pid_value: {unicode} The value for the process identifier.
    :return: {output message, json result, execution state}
    """
    entities_to_process = []
    output_message = u''
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS
                         or entity.entity_type == EntityTypes.HOSTNAME]

    not_found_entities = []
    duplicate_entities = []
    matched_entities = []

    try:
        hosts = manager.get_hosts()
        for entity in suitable_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            host_id = find_in_host(entity, hosts)
            if not host_id:
                not_found_entities.append(entity.identifier)
            else:
                if entity not in matched_entities:
                    matched_entities.append(entity)
                    entities_to_process.append({u"entity": entity.identifier, u"host_id": host_id})
                else:
                    duplicate_entities.append(entity.identifier)

    except Exception as e:
        err_msg = u"An error occurred performing action {}".format(SCRIPT_NAME)
        siemplify.LOGGER.error(err_msg)
        siemplify.LOGGER.exception(e)

    if not_found_entities:
        output_message += u"\n\nAction was not able to find matching McAfee Mvision EDR endpoints for the following " \
                          u"entities: {}" \
            .format(u"\n".join([not_found for not_found in not_found_entities]))

    if duplicate_entities:
        output_message += u"\n\nMultiple matches were found in McAfee Mvision EDR, taking first match for the " \
                          u"following entities: {}" \
            .format(u"\n".join([duplicate_entity for duplicate_entity in duplicate_entities]))

    if entities_to_process:
        output_message += u"\n\nStarted processing entities: {}"\
            .format(u"\n".join([matched_entity.identifier for matched_entity in matched_entities]))
        return output_message, json.dumps(([], entities_to_process, [], [], {}, not_found_entities, duplicate_entities)), EXECUTION_STATE_INPROGRESS

    output_message = u"Action wasn't able to stop the process with {} {} on any entities.".format(pid_type, pid_value)
    return output_message, u"false", EXECUTION_STATE_COMPLETED


def query_operation_status(siemplify, manager, processed_entities, entities_to_process, failed_entities, failed_entities_with_reason, current_entity, not_found_entities, duplicate_entities, pid_type, pid_value):
    """
    Main KillProcess action
    :param siemplify: SiemplifyAction object
    :param manager: McAfeeMvisionEDRManager object
    :param processed_entities: list of processed entities
    :param entities_to_process: list of entities not processed
    :param failed_entities: list of failed entities
    :param failed_entities_with_reason: list of failed entities with reason
    :param current_entity: the entity currently being processed
    :param pid_type: {unicode} Process identifier type.
    :param pid_value: {unicode} The value for the process identifier.
    :return: {output message, json result, execution state}
    """
    result_value = u"false"

    if not current_entity:
        current_entity = process_next_entity(siemplify, entities_to_process, manager, pid_type, pid_value)

    action_status = get_status(manager, current_entity.get(u"task_id"), get_error=False).status

    if action_status == IN_PROGRESS_STATUS:
        output_message = u"Continuing... processing entity: {}".format(current_entity.get(u"entity"))
        return output_message, json.dumps((processed_entities, entities_to_process, failed_entities,
                                           failed_entities_with_reason, current_entity, not_found_entities,
                                           duplicate_entities)), EXECUTION_STATE_INPROGRESS

    output_message = u""
    if action_status == COMPLETED_STATUS:
        result_value = u"true"
        processed_entities.append(current_entity.get(u"entity"))
        output_message += u"Successfully stopped process with {} {} from the following entity: {}" \
            .format(pid_type, pid_value, current_entity.get(u"entity"))
    elif action_status == ERROR_STATUS:
        failed_entities.append(current_entity.get(u"entity"))
        output_message += u"Action wasn't able to stop the process with {} {} from: {}" \
            .format(pid_type, pid_value, current_entity.get(u"entity"))
    elif action_status == COMPLETED_ERROR_STATUS:
        errors = get_status(manager, current_entity.get(u"task_id"), get_error=True)
        fail_entity = {u"entity": current_entity.get(u"entity")}
        if errors.descriptions:
            fail_entity[u"reason"] = u"\n".join([err.desc for err in errors.descriptions])
        failed_entities_with_reason.append(fail_entity)
        output_message += u"Action wasn't able to stop the process with {} {} from {}.".format(pid_type, pid_value,
                                                                                               fail_entity.get(u"entity"))
        if errors.descriptions:
            output_message += u" Reason: {}".format(fail_entity.get(u"reason"))

    if entities_to_process:
        current_entity = process_next_entity(siemplify, entities_to_process, manager, pid_type, pid_value)
        return output_message, json.dumps(
            (processed_entities, entities_to_process, failed_entities, failed_entities_with_reason,
             current_entity, not_found_entities, duplicate_entities)), EXECUTION_STATE_INPROGRESS

    output_message = u""
    if processed_entities:
        result_value = u"true"
        output_message += u"Successfully stopped process with {} {} from the following entities: {}" \
            .format(pid_type, pid_value,
                    u"\n".join([processed_entity for processed_entity in processed_entities]))

    if failed_entities:
        output_message += u"\n\nAction wasn't able to stop the process with {} {} from the following entities: {}" \
            .format(pid_type, pid_value, u"\n".join([failed_entity for failed_entity in failed_entities]))

    if failed_entities_with_reason:
        for item in failed_entities_with_reason:
            output_message += u"\n\nAction wasn't able to stop the process with {} {} from {}.".format(pid_type,
                                                                                                       pid_value, item.get(u"entity"))
            if item.get(u"reason"):
                output_message += u" Reason: {}".format(item.get(u"reason"))

    if not_found_entities:
        output_message += u"\n\nAction was not able to find matching McAfee Mvision EDR endpoints for the following " \
                          u"entities: {}" \
            .format(u"\n".join([not_found for not_found in not_found_entities]))

    if duplicate_entities:
        output_message += u"\n\nMultiple matches were found in McAfee Mvision EDR, taking first match for the " \
                          u"following entities: {}" \
            .format(u"\n".join([duplicate_entity for duplicate_entity in duplicate_entities]))

    return output_message, result_value, EXECUTION_STATE_COMPLETED


def process_next_entity(siemplify, entities_to_process, manager, pid_type, pid_value):
    """
    Get next entity in queue
    :param entities_to_process: entities to be processed
    :param manager: McAfeeMvisionEDRManager object
    :param pid_type: {unicode} Process identifier type.
    :param pid_value: {unicode} The value for the process identifier.
    :return: new_entity_to_process
    """
    try:
        new_entity_to_process = entities_to_process.pop(0)
        host_id = new_entity_to_process.get(u"host_id")
        task_id = manager.kill_process(host_id, pid_type, pid_value).status_id
        new_entity_to_process[u"task_id"] = task_id
        return new_entity_to_process
    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        return None


def get_status(manager, action_id, get_error):
    """
    Get action status
    :param manager: McAfeeMvisionEDRManager object
    :param action_id: created task status id
    :param get_error: defines if the error message should be retrieved
    :return: {status of the action}
    """
    return manager.get_action_status(action_id, get_error)

@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    mode = u"Main" if is_first_run else u"QueryState"

    siemplify.LOGGER.info(u"----------------- {} - Param Init -----------------".format(mode))

    # Configuration.
    api_root = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"API Root",
                                           input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Username",
                                           input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Password",
                                           input_type=unicode)
    client_id = extract_configuration_param(
        siemplify, provider_name=PROVIDER_NAME, param_name="Client ID", input_type=unicode
    )
    client_secret = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Client Secret",
        input_type=unicode,
    )
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    # Parameters
    pid_type = extract_action_param(
        siemplify,
        param_name=u"Process Identifier Type",
        is_mandatory=True,
        input_type=unicode
    )
    pid_value = extract_action_param(
        siemplify,
        param_name=u"Process Identifier",
        is_mandatory=True,
        input_type=unicode
    )

    siemplify.LOGGER.info(u"----------------- {} - Started -----------------".format(mode))

    try:
        mvision_edr_manager = McAfeeMvisionEDRManager(
            api_root, username, password, client_id, client_secret, verify_ssl=verify_ssl
        )

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify, mvision_edr_manager, pid_type, pid_value)
        else:
            processed_entities, entities_to_process, failed_entities, failed_entities_with_reason, current_entity, not_found_entities, duplicate_entities = json.loads(siemplify.parameters[u"additional_data"])
            output_message, result_value, status = query_operation_status(siemplify, mvision_edr_manager,
                                                                          processed_entities, entities_to_process,
                                                                          failed_entities, failed_entities_with_reason,
                                                                          current_entity, not_found_entities,
                                                                          duplicate_entities, pid_type, pid_value)

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Error executing action {}. Reason: {}".format(SCRIPT_NAME, e)

    siemplify.LOGGER.info(u"----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(is_first_run)
