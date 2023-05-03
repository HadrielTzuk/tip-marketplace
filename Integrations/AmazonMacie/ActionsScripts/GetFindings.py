from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

import utils
from AmazonMacieManager import AmazonMacieManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from consts import INTEGRATION_NAME

SCRIPT_NAME = "Get Findings"


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

    findings_ids = extract_action_param(siemplify, param_name="Finding ID", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = "false"
    output_message = ""
    status = EXECUTION_STATE_COMPLETED

    json_results = {}

    try:
        # Split the findings IDs
        findings_ids = utils.load_csv_to_list(findings_ids, "Finding ID")

        siemplify.LOGGER.info('Connecting to Amazon Macie Service')
        manager = AmazonMacieManager(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                                     aws_default_region=aws_default_region)
        manager.test_connectivity()  # this validates the credentials
        siemplify.LOGGER.info("Successfully connected to Amazon Macie service")

        siemplify.LOGGER.info(f"Fetching findings details.")
        findings = manager.get_findings_by_ids(findings_ids=findings_ids)

        if findings:
            siemplify.LOGGER.info(f"Found {len(findings)} findings details.")
            siemplify.result.add_data_table(
                "Amazon Macie Findings", construct_csv([finding.as_csv() for finding in findings])
            )

            found_findings_ids = [finding.id for finding in findings]
            not_found_ids = []

            for findings_id in findings_ids:  # check which finding details wasn't retrieved
                if findings_id not in found_findings_ids:
                    not_found_ids.append(findings_id)

            if found_findings_ids:
                output_message += "Successfully retrieved information for the following findings:\n{}\n\n".format(
                    '\n'.join(found_findings_ids)
                )
                result_value = "true"

            if not_found_ids:
                output_message += "Failed to retrieve information for the following findings:\n{}".format(
                    '\n'.join(not_found_ids)
                )

        else:
            siemplify.LOGGER.info(f"No findings details were found.")
            output_message += "Failed to retrieve information for the following findings:\n{}".format(
                '\n'.join(findings_ids)
            )

        json_results = {finding.id: finding.raw_data for finding in findings}

    except Exception as error:  # action failed
        siemplify.LOGGER.error(f"Failed to connect to the Amazon Macie service! Error is {error}")
        siemplify.LOGGER.exception(error)
        status = EXECUTION_STATE_FAILED
        output_message = f"Failed to connect to the Amazon Macie service! Error is {error}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
