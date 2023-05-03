import json

from TIPCommon import extract_configuration_param, extract_action_param

from AWSSecurityHubManager import AWSSecurityHubManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, MAPPED_GROUP_BY_ATTRIBUTE
from exceptions import AWSSecurityHubStatusCodeException, AWSSecurityHubValidationException
from UtilsManager import validate_filter_json_object
SCRIPT_NAME = "CreateInsight"


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

    insight_name = extract_action_param(siemplify, param_name="Insight Name", is_mandatory=True, print_value=True)

    group_by_attribute = extract_action_param(siemplify, param_name="Group By Attribute", is_mandatory=True,
                                              print_value=True)

    filter_json = extract_action_param(siemplify, param_name="Filter JSON Object", is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = "true"
    output_message = ""
    status = EXECUTION_STATE_COMPLETED

    json_results = {}

    try:
        siemplify.LOGGER.info("Parsing Filter JSON Object.")
        filter_json = validate_filter_json_object(filter_json)
        siemplify.LOGGER.info("Successfully parsed Filter JSON Object.")

        siemplify.LOGGER.info("Successfully parsed Filter JSON Object.")

        group_by_attribute = MAPPED_GROUP_BY_ATTRIBUTE.get(group_by_attribute)

        if not group_by_attribute:  # validate group by attribute
            raise AWSSecurityHubValidationException("Failed to validate Group By Attribute.")

        siemplify.LOGGER.info('Connecting to AWS Security Hub Service')
        hub_client = AWSSecurityHubManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                           aws_default_region=aws_default_region)
        hub_client.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info("Successfully connected to AWS Security Hub service")

        siemplify.LOGGER.info(f"Creating insight {insight_name}")
        insight_arn = hub_client.create_insight(insight_name=insight_name,
                                                filter_json=filter_json,
                                                group_by_attribute=group_by_attribute)

        siemplify.LOGGER.info(f"Successfully created {insight_name} in AWS Security Hub")
        output_message += f"Successfully created {insight_name} in AWS Security Hub"

        json_results['InsightArn'] = insight_arn

    except (AWSSecurityHubStatusCodeException, AWSSecurityHubValidationException) as error:
        result_value = "false"
        siemplify.LOGGER.error(f"Action wasn’t able to create {insight_name} insight. Reason: {error}")
        siemplify.LOGGER.exception(error)
        output_message += f"Action wasn’t able to create {insight_name} insight. Reason: {error}"

    except Exception as error:  # action failed
        siemplify.LOGGER.error(f"Error executing action 'Create Insight'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Error executing action 'Create Insight'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
