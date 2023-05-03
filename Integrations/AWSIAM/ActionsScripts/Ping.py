from AWSIAMManager import AWSIAMManager
from TIPCommon import extract_configuration_param
from consts import INTEGRATION_NAME, PING

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {PING}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    #  INIT INTEGRATION CONFIGURATION:
    aws_access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Access Key ID",
                                                 is_mandatory=True)

    aws_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name="AWS Secret Key",
                                                 is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = AWSIAMManager(aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key)

        siemplify.LOGGER.info('Connecting to AWS IAM Server..')
        manager.test_connectivity()
        siemplify.LOGGER.info('Successfully connected to the AWS IAM server with the provided connection parameters!')

        status = EXECUTION_STATE_COMPLETED
        output_message = "Successfully connected to the AWS IAM server with the provided connection parameters!"
        result_value = True

    except Exception as error:
        siemplify.LOGGER.error(f"Failed to connect to the AWS IAM server! Error is {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Failed to connect to the AWS IAM server! Error is {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
