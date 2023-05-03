from TIPCommon import extract_configuration_param, extract_action_param
from AWSGuardDutyManager import AWSGuardDutyManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from consts import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME
import utils

SCRIPT_NAME = "Delete a Trusted IP List"


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

    detector_id = extract_action_param(siemplify, param_name="Detector ID", is_mandatory=True, print_value=True)
    ip_lists_ids = extract_action_param(siemplify, param_name="Trusted IP List IDs", is_mandatory=True, print_value=True)

    # Split the ip lists IDs
    ip_lists_ids = utils.load_csv_to_list(ip_lists_ids, "Trusted IP List IDs")

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = "false"
    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    successful_ids = []
    failed_ids = []

    try:
        siemplify.LOGGER.info(f'Connecting to {INTEGRATION_DISPLAY_NAME} Service')
        manager = AWSGuardDutyManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                      aws_default_region=aws_default_region)
        manager.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info(f"Successfully connected to {INTEGRATION_DISPLAY_NAME} service")

        manager.get_detector(detector_id=detector_id)  # Validate that the detector exists

        for ip_list_id in ip_lists_ids:
            try:
                siemplify.LOGGER.info(f"Deleting IP list {ip_list_id} details (detector {detector_id})")
                manager.delete_ip_set_by_id(detector_id=detector_id, ip_set_id=ip_list_id)
                successful_ids.append(ip_list_id)

            except Exception as e:
                failed_ids.append(ip_list_id)
                siemplify.LOGGER.error(f"An error occurred on IP list {ip_list_id}")
                siemplify.LOGGER.exception(e)

        if successful_ids:
            output_message += "Successfully deleted the following Trusted IP lists:\n{}\n\n".format(
                '\n'.join(successful_ids)
            )
            result_value = "true"

        if failed_ids:
            output_message += "Action wasn't able to  delete the following Trusted IP Lists from AWS GuardDuty:\n{}".format(
                '\n'.join(failed_ids)
            )

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
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
