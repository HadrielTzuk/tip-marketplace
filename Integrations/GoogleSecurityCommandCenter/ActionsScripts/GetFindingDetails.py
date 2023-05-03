from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from GoogleSecurityCommandCenterManager import GoogleSecurityCommandCenterManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, GET_FINDING_DETAILS_SCRIPT_NAME
from UtilsManager import convert_comma_separated_to_list, convert_list_to_comma_string
from GoogleSecurityCommandCenterExceptions import GoogleSecurityCommandCenterInvalidJsonException, \
    GoogleSecurityCommandCenterInvalidProject


TABLE_NAME = "Finding Details"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_FINDING_DETAILS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    organization_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Organization ID", print_value=True)
    service_account_string = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                         param_name="User's Service Account", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # Action parameters
    finding_name = extract_action_param(siemplify, param_name="Finding Name", is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_names, failed_names, json_results, table_results = [], [], [], []
    finding_names = convert_comma_separated_to_list(finding_name)

    try:
        manager = GoogleSecurityCommandCenterManager(api_root=api_root, organization_id=organization_id,
                                                     service_account_string=service_account_string,
                                                     verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        manager.test_connectivity()

        for name in finding_names:
            try:
                finding_details = manager.get_finding_details(finding_name=name)

                if finding_details:
                    successful_names.append(name)
                    for detail in finding_details:
                        json_results.append(detail.as_json())
                        table_results.append(detail.to_table())
                else:
                    failed_names.append(name)
            except Exception as e:
                siemplify.LOGGER.error(f"Failed processing finding: {name}: Error is: {e}")
                failed_names.append(name)

        if successful_names:
            output_message = f"Successfully returned details about the following findings in " \
                             f"{INTEGRATION_DISPLAY_NAME}: {convert_list_to_comma_string(successful_names)}\n\n"
            siemplify.result.add_result_json(json_results)
            siemplify.result.add_data_table(TABLE_NAME, construct_csv(table_results))

        if failed_names:
            output_message += f"Action wasn't able to find the following findings in " \
                              f"{INTEGRATION_DISPLAY_NAME}: {convert_list_to_comma_string(failed_names)}\n"

        if not successful_names:
            result = False
            output_message = f"None of the provided findings were found in {INTEGRATION_DISPLAY_NAME}"

    except GoogleSecurityCommandCenterInvalidProject:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Project_id was not found in JSON payload provided in the parameter " \
                         "\"User's Service Account\". Please check."
    except GoogleSecurityCommandCenterInvalidJsonException:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Invalid JSON payload provided in the parameter \"User's Service Account\". Please " \
                         "check the structure."
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {GET_FINDING_DETAILS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{GET_FINDING_DETAILS_SCRIPT_NAME}.\" Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
