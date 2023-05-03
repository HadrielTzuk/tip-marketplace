from TIPCommon import extract_configuration_param, extract_action_param
from AWSGuardDutyManager import AWSGuardDutyManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME


SCRIPT_NAME = "List Detectors"

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

    max_detectors = extract_action_param(siemplify, param_name='Max Detectors To Return', input_type=int,
                                         is_mandatory=False, print_value=True, default_value=50)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    json_results = {}

    try:
        siemplify.LOGGER.info(f'Connecting to {INTEGRATION_DISPLAY_NAME} Service')
        manager = AWSGuardDutyManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                      aws_default_region=aws_default_region)
        manager.test_connectivity()
        siemplify.LOGGER.info(f"Successfully connected to {INTEGRATION_DISPLAY_NAME} service")

        siemplify.LOGGER.info("Fetching the detectors list")
        detector_ids = manager.list_detectors(max_results=max_detectors)
        siemplify.LOGGER.info("Successfully fetched the detectors")

        json_results = {'detectorIds': detector_ids}
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully listed available detectors in AWS GuardDuty. Indicator ID: {detector_ids}"
        result_value = "true"

    except Exception as error:
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
