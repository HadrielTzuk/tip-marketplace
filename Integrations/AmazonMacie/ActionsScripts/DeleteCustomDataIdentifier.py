from TIPCommon import extract_configuration_param, extract_action_param

from AmazonMacieManager import AmazonMacieManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME

SCRIPT_NAME = "Delete Custom Data Identifier"


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

    custom_data_id = extract_action_param(siemplify, param_name="Custom Data Identifier ID", is_mandatory=False,
                                          print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = "false"
    status = EXECUTION_STATE_COMPLETED

    try:
        siemplify.LOGGER.info('Connecting to Amazon Macie Service')
        manager = AmazonMacieManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                     aws_default_region=aws_default_region)
        manager.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info("Successfully connected to Amazon Macie service")

        try:
            siemplify.LOGGER.info(f"Deleting custom data identifier {custom_data_id}")
            manager.delete_custom_data_identifier(
                custom_data_id=custom_data_id
            )
            siemplify.LOGGER.info(f"Successfully deleted custom data identifier {custom_data_id} in Amazon Macie")
            output_message = f'Amazon Macie custom data identifier {custom_data_id} deleted'
            result_value = "true"
        except Exception as error: # action failed
            siemplify.LOGGER.error(f'Failed to delete Amazon Macie Identifier {custom_data_id}. Error is: {error}')
            siemplify.LOGGER.exception(error)
            output_message = f'Failed to delete Amazon Macie Identifier {custom_data_id}. Error is: {error}'

    except Exception as error:  # critical error
        siemplify.LOGGER.error(f"Failed to connect to the Amazon Macie service! Error is {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        output_message = f"Failed to connect to the Amazon Macie service! Error is {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
