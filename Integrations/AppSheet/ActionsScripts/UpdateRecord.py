from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from AppSheetManager import AppSheetManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, UPDATE_RECORD_SCRIPT_NAME

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_RECORD_SCRIPT_NAME
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
    json_query = extract_action_param(siemplify, param_name="Record JSON Object", is_mandatory=True, print_value=True)

    try:
        appsheet_manager = AppSheetManager(api_root=api_root, app_id=app_id, access_token=access_token, verify_ssl=verify_ssl,
                         siemplify_logger=siemplify.LOGGER)
        record_details = appsheet_manager.update_record(table_name=table_name, query=json_query)
        
        siemplify.result.add_result_json(record_details)
        result = True
        status = EXECUTION_STATE_COMPLETED
        output_message = f"Successfully updated record in table \"{table_name}\" in {INTEGRATION_DISPLAY_NAME}"

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {UPDATE_RECORD_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{UPDATE_RECORD_SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)

if __name__ == '__main__':
    main()
