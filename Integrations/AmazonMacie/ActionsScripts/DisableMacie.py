from TIPCommon import extract_configuration_param

from AmazonMacieManager import AmazonMacieManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME

SCRIPT_NAME = "Disable Macie"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="AWS Secret Key",
                                                 is_mandatory=True)

    aws_default_region = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                     param_name="AWS Default Region",
                                                     is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = "false"

    try:
        siemplify.LOGGER.info('Connecting to Amazon Macie Service')
        manager = AmazonMacieManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                     aws_default_region=aws_default_region)
        manager.test_connectivity()
        siemplify.LOGGER.info("Successfully connected to Amazon Macie service")
        try:
            manager.disable_macie()
            siemplify.LOGGER.info("Successfully disabled Amazon Macie service")
            output_message = "Successfully disabled Amazon Macie service"
            result_value = "true"
        except Exception as error:
            siemplify.LOGGER.error(f"Failed to disable Amazon Macie service. Error is: {error}")
            siemplify.LOGGER.exception(error)
            output_message = f"Failed to disable Amazon Macie service. Error is: {error}"

    except Exception as error:
        siemplify.LOGGER.error("Failed to connect to the Amazon Macie server! Error is: {}".format(error))
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        output_message = "Failed to connect to the Amazon Macie server! Error is: {}".format(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
