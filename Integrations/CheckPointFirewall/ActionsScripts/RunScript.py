from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_FAILED, EXECUTION_STATE_COMPLETED, EXECUTION_STATE_TIMEDOUT
from CheckpointManager import CheckpointManager
from constants import RUN_SCRIPT_SCRIPT_NAME, INTEGRATION_NAME, SLEEP_TIME
import time


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RUN_SCRIPT_SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Server Address",
                                                 is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    domain_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Domain",
                                              is_mandatory=False, default_value="")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    command = extract_action_param(siemplify, param_name="Script text", is_mandatory=True, print_value=True)
    targets = extract_action_param(siemplify, param_name="Target", is_mandatory=True, print_value=True)
    targets = [target.strip() for target in targets.split(",")]

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    json_results = {}
    checkpoint_manager = None
    result_value = "false"
    task_errors = []
    output_message = ""
    task_messages = []
    status = EXECUTION_STATE_COMPLETED

    try:
        siemplify.LOGGER.info("Connecting to Checkpoint Firewall")
        checkpoint_manager = CheckpointManager(server_address, username, password, domain_name, verify_ssl)

        siemplify.LOGGER.info("Initiating run-script command.")
        task_id = checkpoint_manager.run_script(command, targets)

        siemplify.LOGGER.info("Task ID: {}. Waiting for completion.".format(task_id))

        while not checkpoint_manager.is_task_completed(task_id):
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error("Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                output_message = "Timeout waiting for script completion: {}".format(command)
                break

            siemplify.LOGGER.info("Task {} is not yet completed. Waiting.".format(task_id))
            time.sleep(SLEEP_TIME)

        else:
            # Task has completed and no timeout occurred (no break)
            siemplify.LOGGER.info("Task {} has finished with status {}".format(
                task_id,
                checkpoint_manager.get_task_status(task_id)
            ))

            siemplify.LOGGER.info("Fetching task details.")
            json_results = checkpoint_manager.get_task_details(task_id)

            try:
                # Collect errors from responseError fields from task details
                task_errors = checkpoint_manager.get_task_response_errors(task_id)
            except Exception as e:
                siemplify.LOGGER.error("Unable to collect errors from task details.")
                siemplify.LOGGER.exception(e)

            try:
                # Collect messages from responseMessage fields from task details
                task_messages = checkpoint_manager.get_task_response_messages(task_id)
            except Exception as e:
                siemplify.LOGGER.error("Unable to collect messages from task details.")
                siemplify.LOGGER.exception(e)

            if checkpoint_manager.is_task_succeeded(task_id):
                # Task completed successfully
                output_message = "Script executed successfully."
                result_value = "true"

            else:
                # Task has failed
                output_message = "Failed to execute provided script."

            if task_messages or task_errors:
                output_message += "\n\nScript output:\n   {}\n   {}".format(
                    "\n   ".join([msg for msg in task_messages]),
                    "\n   ".join([error for error in task_errors])
                )
        checkpoint_manager.log_out()
    except Exception as e:
        siemplify.LOGGER.error("Failed to execute action! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "Failed to execute action! Error is {}".format(e)

    siemplify.result.add_result_json(json_results)
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
