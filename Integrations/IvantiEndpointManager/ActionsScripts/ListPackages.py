from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from IvantiEndpointManagerManager import IvantiEndpointManagerManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, LIST_PACKAGES_SCRIPT_NAME


TABLE_NAME = "Available Packages"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_PACKAGES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    # Action parameters
    filter_logic = extract_action_param(siemplify, param_name="Filter Logic", print_value=True)
    filter_value = extract_action_param(siemplify, param_name="Filter Value", print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Packages To Return", input_type=int, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    json_results = {}

    try:
        if limit is not None and limit < 1:
            raise Exception("\"Max Packages To Return\" must be greater than 0.")

        manager = IvantiEndpointManagerManager(api_root=api_root, username=username, password=password,
                                               verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        packages = manager.get_packages(filter_logic, filter_value, limit)

        if packages:
            json_results["DistributionPackages"] = [package.to_json() for package in packages]
            siemplify.result.add_result_json(json_results)
            siemplify.result.add_data_table(TABLE_NAME, construct_csv([package.to_table() for package in packages]))
            output_message += f"Successfully found packages for the provided criteria in {INTEGRATION_DISPLAY_NAME}."
        else:
            output_message = f"No packages were found for the provided criteria in {INTEGRATION_DISPLAY_NAME}."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_PACKAGES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_PACKAGES_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
