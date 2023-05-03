from TIPCommon import extract_configuration_param

from AWSIAMAnalyzerManager import AWSIAMAnalyzerManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME

SCRIPT_NAME = "Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
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

    analyzer_name = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Analyzer Name",
                                                is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        siemplify.LOGGER.info("Connecting to the {} server".format(INTEGRATION_NAME))
        manager = AWSIAMAnalyzerManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                        aws_default_region=aws_default_region, analyzer_name=analyzer_name)
        manager.test_connectivity()
        status = EXECUTION_STATE_COMPLETED
        output_message = "Successfully connected to the {} server with the provided connection parameters!".format(
            INTEGRATION_NAME)
        result_value = "true"

    except Exception as e:
        siemplify.LOGGER.error("Failed to connect to the {} server! Error is {}".format(INTEGRATION_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "Failed to connect to the {} server! Error is {}".format(INTEGRATION_NAME, e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
