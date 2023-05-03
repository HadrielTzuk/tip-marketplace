from AWSCloudWatchManager import AWSCloudWatchManager
from TIPCommon import extract_configuration_param, extract_action_param
from consts import INTEGRATION_DISPLAY_NAME, CREATE_LOG_GROUP

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_DISPLAY_NAME} - {CREATE_LOG_GROUP}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_DISPLAY_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_DISPLAY_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    aws_default_region = extract_configuration_param(siemplify, provider_name=INTEGRATION_DISPLAY_NAME,
                                                     param_name="AWS Default Region",
                                                     is_mandatory=True)

    log_group_name = extract_action_param(siemplify,
                                          param_name='Log Group Name',
                                          is_mandatory=True,
                                          print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = AWSCloudWatchManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                       aws_default_region=aws_default_region)
        manager.create_log_group(log_group_name=log_group_name)
        output_message = f"Successfully created a new log group {log_group_name} in {INTEGRATION_DISPLAY_NAME}"
        siemplify.result.add_result_json({'group_name': log_group_name})
        status = EXECUTION_STATE_COMPLETED
        result_value = True

    except Exception as e:
        output_message = f"Error executing action '{CREATE_LOG_GROUP}'. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
