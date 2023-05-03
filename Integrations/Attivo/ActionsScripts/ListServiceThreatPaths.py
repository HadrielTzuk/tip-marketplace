from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from AttivoManager import AttivoManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, LIST_SERVICE_THREATPATHS_SCRIPT_NAME
from TIPCommon import construct_csv
from UtilsManager import convert_comma_separated_to_list


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_SERVICE_THREATPATHS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    # Action parameters
    services = extract_action_param(siemplify, param_name="Services", print_value=True, is_mandatory=True)
    limit = extract_action_param(siemplify, param_name="Max ThreatPaths To Return", input_type=int, default_value=50,
                                 print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    successful_services, failed_services, json_results = [], [], []

    try:
        services = convert_comma_separated_to_list(services)
        if limit is not None:
            if limit < 1:
                raise Exception(f"Invalid value was provided for \"Max ThreatPaths to Return\": {limit}. "
                                f"Positive number should be provided")

        manager = AttivoManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl,
                                siemplify_logger=siemplify.LOGGER)

        for service in services:
            threatpaths = manager.get_service_threatpaths(service, limit)
            if threatpaths:
                successful_services.append(service)
                siemplify.result.add_data_table(service, construct_csv([path.to_csv() for path in threatpaths]))
                json_results.append({"service": service, "paths": [path.to_json() for path in threatpaths]})
            else:
                failed_services.append(service)

        if successful_services:
            output_message = f'Successfully retrieved ThreatPaths for the following services in  ' \
                             f'{INTEGRATION_DISPLAY_NAME}: ' \
                             f'{", ".join(successful_services)}\n'
            siemplify.result.add_result_json(json_results)

            if failed_services:
                output_message += f'No ThreatPaths were found for the following services in ' \
                                   f'{INTEGRATION_DISPLAY_NAME}: {", ".join(failed_services)}\n'
        else:
            output_message = f"No ThreatPaths were found for the provided services in {INTEGRATION_DISPLAY_NAME}."
            result = False

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_SERVICE_THREATPATHS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_SERVICE_THREATPATHS_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
