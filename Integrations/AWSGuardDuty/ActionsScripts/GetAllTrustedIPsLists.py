from TIPCommon import extract_configuration_param, extract_action_param
from AWSGuardDutyManager import AWSGuardDutyManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, DEFAULT_MAX_RESULTS

SCRIPT_NAME = "Get all Trusted IP lists"


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

    aws_region = extract_action_param(siemplify, param_name="AWS Region", is_mandatory=False, print_value=True,
                                      default_value=aws_default_region)

    detector_id = extract_action_param(siemplify, param_name="Detector ID", is_mandatory=True, print_value=True)

    max_results_to_return = extract_action_param(siemplify, param_name="Max Trusted IP Lists To Return",
                                                 is_mandatory=False,
                                                 print_value=True, input_type=int)

    if max_results_to_return and max_results_to_return < 0:
        max_results_to_return = DEFAULT_MAX_RESULTS
        siemplify.LOGGER.info(
            f"Max Trusted IP Lists To Return parameter must be non-positive. Using default value of {DEFAULT_MAX_RESULTS}")

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = "true"
    status = EXECUTION_STATE_COMPLETED

    json_results = {}

    try:
        siemplify.LOGGER.info('Connecting to AWS GuardDuty Service')
        manager = AWSGuardDutyManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                      aws_default_region=aws_region)
        manager.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info("Successfully connected to AWS GuardDuty service")

        siemplify.LOGGER.info(f"Fetching trusted IP lists ids for detector {detector_id}")
        ip_list_ids = manager.get_trusted_ip_lists_ids(detector_id=detector_id,
                                                       max_results=max_results_to_return)
        siemplify.LOGGER.info(f"Successfully found {len(ip_list_ids)} trusted IP lists ids")
        output_message = f"Successfully retrieved available Trusted IP lists."

        json_results['IpSetIds'] = ip_list_ids

    except Exception as error:  # action failed
        siemplify.LOGGER.error(f"Error executing action '{SCRIPT_NAME}'. Reason: {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f"Error executing action '{SCRIPT_NAME}'. Reason: {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
