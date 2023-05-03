from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from AWSGuardDutyManager import AWSGuardDutyManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from consts import INTEGRATION_NAME
import utils

SCRIPT_NAME = "Get Threat Intelligence Set Details"


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
    ti_sets_ids = extract_action_param(siemplify, param_name="Threat Intelligence Set IDs",is_mandatory=True,
                                       print_value=True)
    aws_region = extract_action_param(siemplify, param_name="AWS Region", is_mandatory=False, print_value=True,
                                      default_value=aws_default_region)

    # Split the ti sets IDs
    ti_sets_ids = utils.load_csv_to_list(ti_sets_ids, "Threat Intelligence Set IDs")

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = "true"
    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    successful_ids = []
    failed_ids = []

    json_results = {}

    try:
        siemplify.LOGGER.info('Connecting to AWS GuardDuty Service')
        manager = AWSGuardDutyManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                      aws_default_region=aws_region)
        manager.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info("Successfully connected to AWS GuardDuty service")

        manager.get_detector(detector_id=detector_id) # Validate that the detector exists

        found_ti_sets = []

        for ti_set_id in ti_sets_ids:
            try:
                siemplify.LOGGER.info(f"Fetching Threat Intelligence set {ti_set_id} details (detector {detector_id})")
                ti_set = manager.get_threat_intel_set_by_id(detector_id=detector_id, threat_intel_set_id=ti_set_id)
                found_ti_sets.append(ti_set)
                successful_ids.append(ti_set_id)
                json_results[ti_set_id] = ti_set.raw_data

            except Exception as e:
                failed_ids.append(ti_set_id)
                siemplify.LOGGER.error(f"An error occurred on Threat Intelligence set {ti_set_id}")
                siemplify.LOGGER.exception(e)

        if found_ti_sets:
            siemplify.LOGGER.info(f"Found {len(found_ti_sets)} Threat Intelligence sets details.")
            siemplify.result.add_data_table(
                "Threat Intelligence Set Details", construct_csv([ti_set.as_csv() for ti_set in found_ti_sets])
            )

            if successful_ids:
                output_message += "Successfully retrieved details about the following Threat Intelligence Sets from AWS GuardDuty:\n{}\n\n".format(
                    '\n'.join(successful_ids)
                )

            if failed_ids:
                output_message += "Action wasn't able to  retrieve details about the following Threat Intelligence Sets from AWS GuardDuty:\n{}".format(
                    '\n'.join(failed_ids)
                )

        else:
            siemplify.LOGGER.info(f"No details were retrieved about the provided Threat Intelligence Sets.")
            output_message += "No details were retrieved about the provided Threat Intelligence Sets."
            result_value = "false"

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
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
