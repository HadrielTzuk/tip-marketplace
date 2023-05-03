from AWSCloudWatchManager import AWSCloudWatchManager
from TIPCommon import extract_configuration_param
from consts import INTEGRATION_DISPLAY_NAME, PING

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_DISPLAY_NAME} - {PING}"
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

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = AWSCloudWatchManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                       aws_default_region=aws_default_region)
        manager.test_connectivity()
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully connected to the {INTEGRATION_DISPLAY_NAME} server with the provided " \
                         f"connection parameters!"
        result_value = True

    except Exception as e:
        output_message = f"Failed to connect to the {INTEGRATION_DISPLAY_NAME} server! Error is: {e}"
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
