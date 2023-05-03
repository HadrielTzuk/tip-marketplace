from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from AppSheetManager import AppSheetManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, SEARCH_RECORDS_SCRIPT_NAME, SEARCH_RECORDS_TABLE_NAME

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEARCH_RECORDS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    app_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="App ID",
                                           is_mandatory=True, print_value=True)
    access_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Access Token",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    table_name = extract_action_param(siemplify, param_name="Table Name", is_mandatory=True, print_value=True)
    selector_query = extract_action_param(siemplify, param_name="Selector Query", is_mandatory=False, print_value=True)

    status = EXECUTION_STATE_COMPLETED
    try:
        appsheet_manager = AppSheetManager(api_root=api_root, app_id=app_id, access_token=access_token, verify_ssl=verify_ssl,
                         siemplify_logger=siemplify.LOGGER)
        record_details = appsheet_manager.search_records(table_name=table_name, query=selector_query)

        if len(record_details) == 0:
            result = False
            output_message = f"No records were found based on the provided criteria in table \"{table_name}\" in {INTEGRATION_DISPLAY_NAME}"
                        
        else:
            siemplify.result.add_result_json([record.to_json() for record in record_details])
            siemplify.result.add_data_table(SEARCH_RECORDS_TABLE_NAME, construct_csv([record.to_table() for record in record_details]))
            result = True
            output_message = f"Successfully retrieved records based on the provided criteria from table \"{table_name}\" in {INTEGRATION_DISPLAY_NAME}"
            
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {SEARCH_RECORDS_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{SEARCH_RECORDS_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)

if __name__ == '__main__':
    main()
