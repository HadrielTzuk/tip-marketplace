from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from Microsoft365DefenderManager import Microsoft365DefenderManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, EXECUTE_QUERY_SCRIPT_NAME, DEFAULT_RESULTS_LIMIT
from UtilsManager import get_timestamps, convert_comma_separated_to_list

TABLE_NAME = "Results"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = EXECUTE_QUERY_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    tenant_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Tenant ID",
                                            is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client Secret",
                                                is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    # Action parameters
    table_names = extract_action_param(siemplify, param_name="Table Names", is_mandatory=True, print_value=True)
    user_query = extract_action_param(siemplify, param_name="Query", print_value=True)
    timeframe = extract_action_param(siemplify, param_name="Time Frame", print_value=True)
    start_time_string = extract_action_param(siemplify, param_name="Start Time", print_value=True)
    end_time_string = extract_action_param(siemplify, param_name="End Time", print_value=True)
    fields_to_return = extract_action_param(siemplify, param_name="Fields To Return", print_value=True)
    sort_field = extract_action_param(siemplify, param_name="Sort Field", print_value=True)
    sort_order = extract_action_param(siemplify, param_name="Sort Order", print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Results To Return", input_type=int, print_value=True,
                                 default_value=DEFAULT_RESULTS_LIMIT)

    table_names = convert_comma_separated_to_list(table_names)
    fields_to_return = convert_comma_separated_to_list(fields_to_return)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = False
    status = EXECUTION_STATE_COMPLETED

    try:
        if limit < 1:
            raise Exception("\"Max Results To Return\" must be greater than 0.")

        start_time, end_time = get_timestamps(timeframe, start_time_string, end_time_string)

        manager = Microsoft365DefenderManager(api_root=api_root, tenant_id=tenant_id, client_id=client_id,
                                              client_secret=client_secret, verify_ssl=verify_ssl,
                                              siemplify=siemplify)
        devices, query_string = manager.search_for_devices(
            table_names=table_names,
            start_time=start_time,
            end_time=end_time,
            user_query=user_query,
            fields=fields_to_return,
            sort_field=sort_field,
            sort_order=sort_order.lower(),
            limit=limit
        )

        if devices:
            result = True
            siemplify.result.add_data_table(TABLE_NAME, construct_csv([device.to_csv() for device in devices]))
            siemplify.result.add_result_json([device.to_json() for device in devices])
            output_message = f"Successfully executed query \"{query_string}\" in {INTEGRATION_DISPLAY_NAME}" if \
                query_string else f"Successfully executed query in {INTEGRATION_DISPLAY_NAME}"
        else:
            output_message = f"No data was found for the query \"{query_string}\" in {INTEGRATION_DISPLAY_NAME}" if \
                query_string else f"No data was found for the query in {INTEGRATION_DISPLAY_NAME}"

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {EXECUTE_QUERY_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"Execute Query.\" Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
