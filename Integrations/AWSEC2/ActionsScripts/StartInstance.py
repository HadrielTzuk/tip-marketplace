import json
import copy
import sys

from TIPCommon import extract_configuration_param, extract_action_param

from AWSEC2Manager import AWSEC2Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, START_INSTANCE, PENDING, RUNNING
from utils import load_csv_to_list
from exceptions import AWSEC2InvalidInstanceIDException, AWSEC2IncorrectInstanceStateException


def start_operation(siemplify, manager, instances_ids):
    status = EXECUTION_STATE_INPROGRESS
    output_message = ''

    not_exists_instances = []
    wrong_status_instances = []
    pending_instances = []
    running_instances = []

    for instance in instances_ids:
        try:
            siemplify.LOGGER.info(f"Starting instance with id: {instance}")
            instance_status = manager.start_instances(instance_ids=[instance])

            if instance_status.current_state == PENDING:
                pending_instances.append(instance_status.as_json())
            elif instance_status.current_state == RUNNING:
                running_instances.append(instance_status.as_json())
            else:
                wrong_status_instances.append(instance_status.as_json())

            siemplify.LOGGER.info(f"Successfully initiated starting process of instance with id: {instance}")

        # If instance doesn't exist in EC2 account
        except AWSEC2InvalidInstanceIDException as error:
            siemplify.LOGGER.exception(error)
            not_exists_instances.append(instance)

        # If instance not in stopped/running/pending state in EC2 account
        except AWSEC2IncorrectInstanceStateException as error:
            siemplify.LOGGER.exception(error)
            wrong_status_instances.append(instance)

    instances_status = {RUNNING: running_instances,
                        PENDING: pending_instances,
                        'not_exists': not_exists_instances,
                        'wrong_status': wrong_status_instances}

    if pending_instances:
        output_message += 'Continuing… the requested instances are still pending'
        siemplify.LOGGER.info(output_message)
        result_value = json.dumps(instances_status)

    elif running_instances:
        output_message, result_value, status = finish_operation(siemplify=siemplify,
                                                                instances_status=instances_status)

    else:
        if wrong_status_instances:
            wrong_status_instances_str = ', '.join(wrong_status_instances)
            output_message += f"Can not start the following instances from their current state: " \
                              f"{wrong_status_instances_str}.\n"
            siemplify.LOGGER.info(output_message)

        if not_exists_instances:
            not_exists_instances_str = ', '.join(not_exists_instances)
            output_message += f"The following instances are not valid: {not_exists_instances_str}. Please try again."
            siemplify.LOGGER.info(output_message)

        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status


def query_operation_status(siemplify, manager, instances_status_dict):
    pending_instances = instances_status_dict.get(PENDING, [])
    copy_pending_instances = copy.deepcopy(instances_status_dict[PENDING])

    # If there are still pending instances
    if pending_instances:
        for instance in pending_instances:
            siemplify.LOGGER.info(f"Starting instance with id: {instance.get('InstanceId')}")
            instance_status = manager.start_instances(instance_ids=[instance.get('InstanceId')])

            if instance_status.current_state == RUNNING:
                copy_pending_instances.remove(instance)
                instance['CurrentState'] = instance_status.current_state
                instances_status_dict[RUNNING] = instances_status_dict.get(RUNNING, [])
                instances_status_dict.get(RUNNING, []).append(instance)

        instances_status_dict[PENDING] = copy_pending_instances

    if not instances_status_dict[PENDING] and instances_status_dict[RUNNING]:
        siemplify.LOGGER.info("All valid input instances ids were processed")
        output_message, result_value, status = finish_operation(siemplify=siemplify,
                                                                instances_status=instances_status_dict)

    else:
        status = EXECUTION_STATE_INPROGRESS
        output_message = 'Continuing… the requested instances are still pending'
        siemplify.LOGGER.info(output_message)
        result_value = json.dumps(instances_status_dict)

    return output_message, result_value, status


def finish_operation(siemplify, instances_status):
    output_message = ''
    siemplify.LOGGER.info("No more instances in pending state")
    result_value = False

    if instances_status.get(RUNNING):
        running_instances_str = ', '.join([instance.get('InstanceId') for instance in instances_status.get(RUNNING)])
        output_message += f"The following instances were started successfully: {running_instances_str}.\n"
        result_value = True

        json_results = instances_status.get(RUNNING)
        siemplify.result.add_result_json(json_results)

    if instances_status.get('wrong_status'):
        wrong_status_instances_str = ', '.join(instances_status.get('wrong_status'))
        output_message += f"Can not start the following instances from their current state: " \
                          f"{wrong_status_instances_str}.\n"
        result_value = False

    if instances_status.get('not_exists'):
        not_exists_instances_str = ', '.join(instances_status.get('not_exists'))
        output_message += f"The following instances are not valid: {not_exists_instances_str}. Please try again.\n"
        result_value = False

    siemplify.LOGGER.info(output_message)

    status = EXECUTION_STATE_COMPLETED
    return output_message, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, START_INSTANCE)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify,
                                                 provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify,
                                                 provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    aws_default_region = extract_configuration_param(siemplify,
                                                     provider_name=INTEGRATION_NAME,
                                                     param_name="AWS Default Region",
                                                     is_mandatory=True)

    instance_ids = extract_action_param(siemplify,
                                        param_name="Instance IDs",
                                        is_mandatory=False,
                                        print_value=True)

    mode = "Main" if is_first_run else {START_INSTANCE}
    siemplify.LOGGER.info(f"----------------- {mode} - Started -----------------")

    try:
        manager = AWSEC2Manager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                aws_default_region=aws_default_region)

        # Split the instances ids if exists
        instance_ids_list = load_csv_to_list(instance_ids, "Instances IDs", ',')

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify=siemplify,
                                                                   manager=manager,
                                                                   instances_ids=instance_ids_list)

        else:
            instances_status = json.loads(siemplify.extract_action_param("additional_data"))
            output_message, result_value, status = query_operation_status(siemplify=siemplify,
                                                                          manager=manager,
                                                                          instances_status_dict=instances_status)

    except Exception as error:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action '{START_INSTANCE}'. Reason: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
