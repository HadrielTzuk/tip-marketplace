from SiemplifyAction import SiemplifyAction
from AnyRunManager import AnyRunManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from constants import (
    INTEGRATION_NAME,
    SEARCH_REPORT_HISTORY_ACTION,
    DEFAULT_SKIP_NUMBER,
    DEFAULT_SEARCH_LIMIT
)

TABLE_HEADER = 'Search Results'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEARCH_REPORT_HISTORY_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configuration.
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key")

    # Parameters
    submission_name = extract_action_param(siemplify, param_name='Submission Name', is_mandatory=False,
                                           print_value=True)
    search_limit = extract_action_param(siemplify, param_name='Search in last x scans', is_mandatory=True,
                                        input_type=int, default_value=DEFAULT_SEARCH_LIMIT, print_value=True)
    skip_number = extract_action_param(siemplify, param_name='Skip first x scans', is_mandatory=False,
                                       input_type=int, default_value=DEFAULT_SKIP_NUMBER, print_value=True)
    get_team_history = extract_action_param(siemplify, param_name='Get team history?', is_mandatory=False,
                                            input_type=bool, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        manager = AnyRunManager(
            api_key=api_key,
            siemplify_logger=siemplify.LOGGER
        )
        all_history_items = manager.get_analysis_history(limit=search_limit, team_history=get_team_history,
                                                         skip=skip_number)
        if submission_name:
            all_history_items = [item for item in all_history_items if item.name == submission_name]
        if all_history_items:
            siemplify.result.add_result_json([history.to_json() for history in all_history_items])
            siemplify.result.add_data_table(title=TABLE_HEADER, data_table=construct_csv(
                [history.to_csv() for history in all_history_items]))
            output_message = "Found Any.Run reports for the provided search parameters."
            result_value = True
        else:
            output_message = "No Any.Run reports were found."

    except Exception as e:
        output_message = "Error executing action \"Search Report History\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        "\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()