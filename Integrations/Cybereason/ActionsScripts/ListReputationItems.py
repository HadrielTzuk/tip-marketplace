from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from CybereasonManager import CybereasonManager, CybereasonManagerNotFoundError
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, LIST_REPUTATION_ITEMS_SCRIPT_NAME, SUPPORTED_FILE_HASH_TYPES,\
    REPUTATION_CASE_WALL_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_REPUTATION_ITEMS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    filter_logic = extract_action_param(siemplify, param_name="Filter Logic", print_value=True)
    filter_value = extract_action_param(siemplify, param_name="Filter Value", print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Results To Return", default_value=50, input_type=int,
                                 print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = CybereasonManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl,
                                    force_check_connectivity=True)

        status = EXECUTION_STATE_COMPLETED
        output_message = f'Successfully found reputation items for the provided criteria in {INTEGRATION_NAME}'
        result_value = True
        json_results = {}
        classifications = manager.get_reputation_list(filter_logic=filter_logic, filter_value=filter_value,
                                                      limit=limit)
        if classifications:
            csv_output = construct_csv([classification.to_csv() for classification in classifications])
            siemplify.result.add_data_table(REPUTATION_CASE_WALL_NAME, csv_output)
            json_results = [classification.to_json() for classification in classifications]
        else:
            output_message = f'No reputation items were found for the provided criteria in {INTEGRATION_NAME}'
            result_value = False
        if json_results:
            siemplify.result.add_result_json(json_results)
    except Exception as e:
        output_message = f"Error executing action {LIST_REPUTATION_ITEMS_SCRIPT_NAME}. Reason: {e}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
