from TIPCommon import extract_configuration_param, extract_action_param

from AWSS3Manager import AWSS3Manager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME
from exceptions import AWSS3StatusCodeException

SCRIPT_NAME = "GetBucketPolicy"


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

    bucket_name = extract_action_param(siemplify, param_name="Bucket Name", is_mandatory=True, print_value=True)
    bucket_name = bucket_name.lower()

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = "true"
    output_message = ""
    status = EXECUTION_STATE_COMPLETED

    json_results = []

    try:
        siemplify.LOGGER.info('Connecting to AWSS3 Service')
        s3_client = AWSS3Manager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                 aws_default_region=aws_default_region)
        s3_client.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info("Successfully connected to AWSS3 service")

        siemplify.LOGGER.info(f"Fetching bucket policy for bucket {bucket_name}")
        bucket_policy = s3_client.get_bucket_policy(bucket_name)
        siemplify.LOGGER.info(
            f"Successfully retrieved information about the policy of the {bucket_name} bucket in AWS S3")
        output_message += f"Successfully retrieved information about the policy of the {bucket_name} bucket in AWS S3"

        json_results.append({
            'Policy': bucket_policy.to_dict()
        })

    except AWSS3StatusCodeException as error:
        result_value = "false"
        siemplify.LOGGER.error(
            f"Action wasn’t able to return information about the policy of the {bucket_name} bucket in AWS S3")
        siemplify.LOGGER.exception(error)
        output_message += f"Action wasn’t able to return information about the policy of the {bucket_name} bucket in AWS S3"

    except Exception as error:  # action failed
        siemplify.LOGGER.error(f"Error executing action 'Get Bucket Policy'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Error executing action 'Get Bucket Policy'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
