from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from AppSheetManager import AppSheetManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, LIST_TABLES_SCRIPT_NAME, LIST_TABLES_TABLE_NAME, EQUAL_FILTER, DEFAULT_LIMIT, CONTAINS_FILTER 

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_TABLES_SCRIPT_NAME
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

    filter_logic = extract_action_param(siemplify, param_name="Filter Logic", print_value=True)
    filter_value = extract_action_param(siemplify, param_name="Filter Value", print_value=True)
    limit = extract_action_param(siemplify, param_name='Max Tables To Return', input_type=int,
                                 print_value=True, default_value=DEFAULT_LIMIT)
    
    status = EXECUTION_STATE_COMPLETED
    result = True
    try:
        if limit < 1:
            raise Exception("\"Max Tables To Return\" must be greater than 0.")
        
        appsheet_manager = AppSheetManager(api_root=api_root, app_id=app_id, access_token=access_token, verify_ssl=verify_ssl,
                         siemplify_logger=siemplify.LOGGER)
        tables = appsheet_manager.list_tables()

        if filter_value:
            if filter_logic == EQUAL_FILTER:
                tables = [table for table in tables if table.name == filter_value]
            elif filter_logic == CONTAINS_FILTER:
                tables = [table for table in tables if filter_value in table.name]

        tables = tables[:limit] if limit else tables

        if tables:
            siemplify.result.add_data_table(LIST_TABLES_TABLE_NAME, construct_csv([table.to_csv() for table in tables]))
            siemplify.result.add_result_json([table.to_json() for table in tables])
            output_message = f'Successfully found tables for the provided criteria in' \
                             f' {INTEGRATION_NAME}.'
        else:
            result = False
            output_message = f'No tables were found for the provided criteria in {INTEGRATION_NAME}.'
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_TABLES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_TABLES_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)

if __name__ == '__main__':
    main()
