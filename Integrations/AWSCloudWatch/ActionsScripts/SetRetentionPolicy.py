from AWSCloudWatchManager import AWSCloudWatchManager
from TIPCommon import extract_configuration_param, extract_action_param
from consts import INTEGRATION_DISPLAY_NAME, SET_RETENTION_POLICY

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_DISPLAY_NAME} - {SET_RETENTION_POLICY}"
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
                                          param_name='Log Group',
                                          is_mandatory=True,
                                          print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        retention_days = extract_action_param(siemplify,
                                              param_name='Retention Days',
                                              input_type=int,
                                              is_mandatory=True,
                                              print_value=True)

        manager = AWSCloudWatchManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                       aws_default_region=aws_default_region)

        siemplify.LOGGER.info(f"Setting new retention policy for log group {log_group_name}..")
        manager.set_retention_policy(log_group_name=log_group_name,
                                     retention_in_days=retention_days)

        output_message = f"Successfully set the retention policy for log group {log_group_name} in " \
                         f"{INTEGRATION_DISPLAY_NAME}"
        status = EXECUTION_STATE_COMPLETED
        result_value = True

    except Exception as e:
        output_message = f"Error executing action '{SET_RETENTION_POLICY}'. Reason: {e}"
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
